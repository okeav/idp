import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { withTemporaryApp, buildTestApp, uniqueEmail } from './helpers/build-test-app.js';
import { json } from './helpers/serve.js';
import { verifyWebhookSignature, WebhookDispatcher } from '../src/index.js';
import { buildSignatureHeader } from '../src/webhooks/sign.js';

// Webhook / hook issues found in the 0.3.0 audit:
//  - every endpoint received live password-reset and magic-link tokens and
//    email-verification codes (anyone with access to a receiver's logs could
//    take over accounts); no per-endpoint event filter; http allowed;
//  - redirects were followed (re-POSTing the signed body elsewhere);
//  - the delivery id wasn't signed; the verify helper took one signature only;
//  - a throwing in-process hook dropped the webhook;
//  - unbounded concurrent deliveries; awaited email hooks made response timing
//    reveal whether an account exists, and a hung hook stalled the request.

async function receiver(status = () => 200) {
    const deliveries = [];
    const server = http.createServer((req, res) => {
        const chunks = [];
        req.on('data', (c) => chunks.push(c));
        req.on('end', () => {
            const rawBody = Buffer.concat(chunks).toString('utf8');
            deliveries.push({ rawBody, body: JSON.parse(rawBody || '{}'), headers: { ...req.headers } });
            const s = status(req);
            if (typeof s === 'object') return res.writeHead(s.status, s.headers).end();
            res.writeHead(s).end();
        });
    });
    await new Promise((r) => server.listen(0, r));
    return { url: `http://127.0.0.1:${server.address().port}/hook`, deliveries, stop: () => new Promise((r) => server.close(r)) };
}

const settle = () => new Promise((r) => setTimeout(r, 300));
const SECRET = 'whsec_test_secret_hardening';

test('credential fields never reach an endpoint unless it opts in with includeCredentials', async () => {
    const analytics = await receiver();
    const mailer = await receiver();
    try {
        await withTemporaryApp({ config: { webhooks: { endpoints: [{ url: analytics.url, secret: SECRET }, { url: mailer.url, secret: SECRET, includeCredentials: true }] } } }, async (temp) => {
            const email = uniqueEmail('wh-cred');
            await fetch(`${temp.baseUrl}/register`, json({ email, password: 'Str0ng!Passw0rd' }));
            await fetch(`${temp.baseUrl}/password/forgot`, json({ email }));
            await fetch(`${temp.baseUrl}/magic-link/request`, json({ email }));
            await settle();

            const byEvent = (r, event) => r.deliveries.find((d) => d.body.event === event)?.body.payload;
            for (const [event, fields] of [['onVerificationEmailRequested', ['verificationToken', 'verificationCode']], ['onPasswordResetRequested', ['resetToken']], ['onMagicLinkRequested', ['magicLinkToken']]]) {
                const redacted = byEvent(analytics, event);
                const full = byEvent(mailer, event);
                assert.ok(redacted, `${event} delivered to analytics`);
                assert.equal(redacted.email, email);
                for (const f of fields) {
                    assert.equal(redacted[f], undefined, `${event}.${f} must not reach a receiver that didn't opt in`);
                    assert.ok(full[f], `${event}.${f} reaches the opted-in mailer`);
                }
            }
        });
    } finally {
        await analytics.stop();
        await mailer.stop();
    }
});

test('an endpoint\'s events list filters what it receives', async () => {
    const r = await receiver();
    try {
        await withTemporaryApp({ config: { webhooks: { endpoints: [{ url: r.url, secret: SECRET, events: ['REGISTERED'] }] } } }, async (temp) => {
            const email = uniqueEmail('wh-filter');
            await fetch(`${temp.baseUrl}/register`, json({ email, password: 'Str0ng!Passw0rd' }));
            await fetch(`${temp.baseUrl}/password/forgot`, json({ email }));
            await settle();
            assert.deepEqual([...new Set(r.deliveries.map((d) => d.body.event))], ['REGISTERED']);
        });
    } finally {
        await r.stop();
    }
});

test('endpoint configuration is validated at startup: https (or loopback http), a real secret', async () => {
    await assert.rejects(buildTestApp({ config: { webhooks: { endpoints: [{ url: 'http://hooks.example.com/x', secret: SECRET }] } } }), /must be https/);
    await assert.rejects(buildTestApp({ config: { webhooks: { endpoints: [{ url: 'https://hooks.example.com/x', secret: 'short' }] } } }), /at least 16/);
    assert.doesNotThrow(() => new WebhookDispatcher({ endpoints: [{ url: 'https://hooks.example.com/x', secret: SECRET }] }));
});

test('a redirecting endpoint is a failed delivery — the signed body is never re-sent to the redirect target', async () => {
    const target = await receiver();
    const redirector = await receiver(() => ({ status: 307, headers: { Location: target.url } }));
    try {
        const d = new WebhookDispatcher({ endpoints: [{ url: redirector.url, secret: SECRET }], maxAttempts: 1 });
        d.dispatch('PING', { a: 1 });
        await settle();
        assert.equal(redirector.deliveries.length, 1);
        assert.equal(target.deliveries.length, 0);
    } finally {
        await target.stop();
        await redirector.stop();
    }
});

test('the delivery id is inside the signed body and matches the header', async () => {
    const r = await receiver();
    try {
        const d = new WebhookDispatcher({ endpoints: [{ url: r.url, secret: SECRET }] });
        d.dispatch('PING', { a: 1 });
        await settle();
        const [delivery] = r.deliveries;
        assert.ok(delivery.body.id);
        assert.equal(delivery.body.id, delivery.headers['x-idp-delivery']);
        assert.equal(verifyWebhookSignature(SECRET, delivery.rawBody, delivery.headers['x-idp-signature']), true);
        assert.equal(verifyWebhookSignature(SECRET, delivery.rawBody.replace(delivery.body.id, 'forged-id'), delivery.headers['x-idp-signature']), false);
    } finally {
        await r.stop();
    }
});

test('verifyWebhookSignature: secret rotation (several secrets / several v1 values), and malformed input', () => {
    const body = JSON.stringify({ id: '1', event: 'X' });
    const t = Math.floor(Date.now() / 1000);
    const oldSig = buildSignatureHeader('old-secret-0123456789', t, body);
    const newSig = buildSignatureHeader('new-secret-0123456789', t, body).split(',')[1];
    assert.equal(verifyWebhookSignature(['new-secret-0123456789', 'old-secret-0123456789'], body, oldSig), true);
    assert.equal(verifyWebhookSignature('new-secret-0123456789', body, `${oldSig},${newSig}`), true, 'any one v1 may match');
    assert.equal(verifyWebhookSignature('other-secret-01234567', body, `${oldSig},${newSig}`), false);
    for (const bad of [undefined, '', 't=,v1=', 'v1=zz', `t=${t}`, `t=${t - 3600},${oldSig.split(',')[1]}`]) {
        assert.equal(verifyWebhookSignature('old-secret-0123456789', body, bad), false, String(bad));
    }
});

test('a throwing in-process hook does not drop the webhook', async () => {
    const r = await receiver();
    try {
        await withTemporaryApp({
            config: { webhooks: { endpoints: [{ url: r.url, secret: SECRET }] } },
            hooks: { onPasswordResetRequested: () => { throw new Error('mailer down'); } },
        }, async (temp) => {
            const email = uniqueEmail('wh-throw');
            await fetch(`${temp.baseUrl}/register`, json({ email, password: 'Str0ng!Passw0rd' }));
            assert.equal((await fetch(`${temp.baseUrl}/password/forgot`, json({ email }))).status, 200);
            await settle();
            assert.ok(r.deliveries.some((d) => d.body.event === 'onPasswordResetRequested'));
        });
    } finally {
        await r.stop();
    }
});

test('concurrent deliveries are bounded by maxInFlight; the excess is dropped with a warning', async () => {
    const hung = http.createServer(() => { /* never answers */ });
    await new Promise((r) => hung.listen(0, r));
    const warnings = [];
    try {
        const d = new WebhookDispatcher({ endpoints: [{ url: `http://127.0.0.1:${hung.address().port}/x`, secret: SECRET }], maxInFlight: 2, maxAttempts: 1, timeoutMs: 300 },
            { warn: (ctx, msg) => warnings.push(msg) });
        for (let i = 0; i < 5; i += 1) d.dispatch('PING', { i });
        assert.equal(d.inFlight, 2);
        assert.equal(warnings.filter((m) => /backlog full/.test(m)).length, 3);
        await new Promise((r) => setTimeout(r, 600));
        assert.equal(d.inFlight, 0, 'timed-out deliveries free their slot');
    } finally {
        hung.closeAllConnections?.();
        await new Promise((r) => hung.close(r));
    }
});

test('a hung hook never stalls the request (hookTimeoutMs)', async () => {
    await withTemporaryApp({ config: { hookTimeoutMs: 200 }, hooks: { onAuditLog: () => new Promise(() => {}) } }, async (temp) => {
        const email = uniqueEmail('hung-hook');
        await fetch(`${temp.baseUrl}/register`, json({ email, password: 'Str0ng!Passw0rd' }));
        const code = temp.hookCalls.onVerificationEmailRequested.filter((c) => c.email === email).at(-1).verificationCode;
        await fetch(`${temp.baseUrl}/register/verify-email`, json({ email, code }));
        const started = Date.now();
        const res = await fetch(`${temp.baseUrl}/login`, json({ email, password: 'Str0ng!Passw0rd' }));
        assert.equal(res.status, 200);
        assert.ok(Date.now() - started < 3000, `took ${Date.now() - started}ms`);
    });
});

test('enumeration-sensitive endpoints answer without waiting for the email hook', async () => {
    let resolveSlow;
    const slow = () => new Promise((r) => { resolveSlow = r; });
    await withTemporaryApp({ hooks: { onPasswordResetRequested: slow, onMagicLinkRequested: slow } }, async (temp) => {
        const email = uniqueEmail('slow-mail');
        await fetch(`${temp.baseUrl}/register`, json({ email, password: 'Str0ng!Passw0rd' }));
        for (const path of ['/password/forgot', '/magic-link/request']) {
            const started = Date.now();
            const res = await fetch(`${temp.baseUrl}${path}`, json({ email }));
            assert.equal(res.status, 200);
            assert.ok(Date.now() - started < 1000, `${path} waited for the (never-finishing) mail hook`);
            resolveSlow?.();
        }
    });
});
