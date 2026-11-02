import { test, before, after, mock } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import { generate as generateTotp } from 'otplib';
import { pkcePair } from './helpers/oauth.js';
import express from 'express';
import cookieParserLib from 'cookie-parser';
import { buildRouter } from '../src/routes/build-router.js';
import { setState } from '../src/config/state.js';
import { refreshCookieBinding, readRefreshCookie } from '../src/utils/cookies.js';
import { buildTestApp, withTemporaryApp, uniqueEmail, waitForHookCall, TEST_SECURITY } from './helpers/build-test-app.js';
import { hashOpaqueToken, HASH_PURPOSES } from '../src/signing/token.service.js';
import { json } from './helpers/serve.js';
import { configFromEnv, checkClockSkew } from '../src/index.js';
import { createMongoStorage } from '../src/storage/mongo/index.js';
import { startClockSkewGuard } from '../src/security/clock-skew.js';

// Closing the limitations left after 0.4.0's second round: the end-session confirmation page, clock
// skew, verification tickets, per-request login challenges and the path-scoped refresh cookie.

const password = 'Str0ng!Passw0rd';
const ISSUER_ORIGIN = 'https://idp.test.local';
let app;

before(async () => {
    app = await buildTestApp();
});

after(async () => {
    await app.stop();
});

const post = (base, path, body, headers) => fetch(`${base}${path}`, json(body, headers));

async function registered(target = app) {
    const email = uniqueEmail('ent');
    await post(target.baseUrl, '/register', { email, password });
    const code = target.hookCalls.onVerificationEmailRequested.filter((c) => c.email === email).at(-1).verificationCode;
    await post(target.baseUrl, '/register/verify-email', { email, code });
    return email;
}

async function loggedIn(target = app) {
    const email = await registered(target);
    return { email, ...(await (await post(target.baseUrl, '/login', { email, password })).json()) };
}

// ── end-session confirmation page ────────────────────────────────────────────

test('with oidc.endSessionConfirmationUrl, a GET that needs confirmation redirects to that page with its parameters', async () => {
    const page = `${ISSUER_ORIGIN}/signout`;
    await withTemporaryApp({ config: { oidc: { endSessionConfirmationUrl: page } } }, async (temp) => {
        const u = await loggedIn(temp);
        const res = await fetch(`${temp.baseUrl}/session/end?state=abc&ui_locales=de`, { headers: { Cookie: `__Host-access_token=${u.accessToken}` }, redirect: 'manual' });
        assert.equal(res.status, 302);
        const to = new URL(res.headers.get('location'));
        assert.equal(`${to.origin}${to.pathname}`, page);
        assert.equal(to.searchParams.get('state'), 'abc');
        assert.equal(to.searchParams.get('ui_locales'), 'de');
        assert.equal((await fetch(`${temp.baseUrl}/me`, { headers: { Authorization: `Bearer ${u.accessToken}` } })).status, 200, 'nothing ended');
    });
});

test('oidc.endSessionConfirmationUrl must be https and on a trusted origin; IDP_OIDC_END_SESSION_CONFIRMATION_URL sets it', async () => {
    await assert.rejects(buildTestApp({ config: { oidc: { endSessionConfirmationUrl: 'http://idp.test.local/signout' } } }), /must be an https URL/);
    await assert.rejects(buildTestApp({ config: { oidc: { endSessionConfirmationUrl: 'https://elsewhere.example/signout' } } }), /issuer's origin or one of cookies.trustedOrigins/);
    await withTemporaryApp({ config: { cookies: { trustedOrigins: ['https://app.example.com'] }, oidc: { endSessionConfirmationUrl: 'https://app.example.com/signout' } } }, async () => {});
    assert.equal(configFromEnv({ IDP_OIDC_END_SESSION_CONFIRMATION_URL: 'https://idp.example/signout' }).oidc.endSessionConfirmationUrl, 'https://idp.example/signout');
});

// ── clock skew ───────────────────────────────────────────────────────────────

/** A storage factory: the real Mongo adapter, with the database's clock `driftMs` away from this server's. */
const driftingStorage = (driftMs) => async (cfg, deps) => {
    const storage = await createMongoStorage(cfg.mongo, deps);
    storage.databaseTime = async () => ({ time: new Date(Date.now() + driftMs) });
    return storage;
};

function captureLogger() {
    const lines = [];
    const log = (level) => (obj, msg) => lines.push({ level, obj, msg });
    return { lines, logger: { debug: log('debug'), info: log('info'), warn: log('warn'), error: log('error') } };
}

test('startup is refused when this server\'s clock is too far from the database\'s', async () => {
    await assert.rejects(buildTestApp({ config: { storage: { factory: driftingStorage(120_000) } } }), /clock is 120\.0s behind the database's \(limit 30s\)/);
    await assert.rejects(buildTestApp({ config: { storage: { factory: driftingStorage(-45_000) } } }), /ahead of the database's/);
});

test('a skew within the limit but past warnSkewSeconds starts with a warning', async () => {
    const { lines, logger } = captureLogger();
    await withTemporaryApp({ config: { logger, storage: { factory: driftingStorage(5_000) } } }, async () => {
        assert.ok(lines.some((l) => l.level === 'warn' && /behind the database's/.test(l.msg ?? '')));
    });
});

test('the skew is re-checked periodically, and logged as an error once past the limit', async () => {
    mock.timers.enable({ apis: ['setInterval'] });
    try {
        let drift = 0;
        const storage = { databaseTime: async () => ({ time: new Date(Date.now() + drift) }) };
        const { lines, logger } = captureLogger();
        const stop = await startClockSkewGuard(storage, { maxSkewSeconds: 30, warnSkewSeconds: 2, checkIntervalSeconds: 60 }, logger);
        drift = 90_000;
        mock.timers.tick(60_000);
        await new Promise((r) => setImmediate(r));
        assert.ok(lines.some((l) => l.level === 'error' && /behind the database's/.test(l.msg ?? '')), JSON.stringify(lines));
        stop();
    } finally {
        mock.timers.reset();
    }
});

test('checkClockSkew() reports the current skew for health checks; clock settings are validated', async () => {
    const result = await checkClockSkew();
    assert.equal(result.ok, true);
    assert.equal(result.level, 'ok');
    assert.ok(Math.abs(result.skewMs) < 2000);
    await assert.rejects(buildTestApp({ config: { clock: { maxSkewSeconds: 0 } } }), /clock.maxSkewSeconds must be an integer >= 1/);
    await assert.rejects(buildTestApp({ config: { clock: { warnSkewSeconds: 40 } } }), /warnSkewSeconds must not exceed maxSkewSeconds/);
    assert.equal(configFromEnv({ IDP_CLOCK_MAX_SKEW_SECONDS: '10' }).clock.maxSkewSeconds, 10);
});

// ── verification tickets ─────────────────────────────────────────────────────

const LOCKOUT = { verificationCodeLockout: { maxFailedAttempts: 3, windowSeconds: 3600, lockSeconds: 3600 } };
const lastCode = (target, email) => target.hookCalls.onVerificationEmailRequested.filter((c) => c.email === email).at(-1);
const ticketCookieOf = (res) => res.headers.getSetCookie().find((c) => c.startsWith('__Host-verification_ticket=')).split(';')[0];

async function strangerLocks(target, email, code) {
    const wrong = code === '123456' ? '654321' : '123456';
    for (let i = 0; i < 3; i += 1) await post(target.baseUrl, '/register/verify-email', { email, code: wrong });
    assert.equal((await post(target.baseUrl, '/register/verify-email', { email, code })).status, 429, 'the address budget is spent');
}

test('the registering browser verifies with its ticket cookie after a stranger used up the address budget', async () => {
    await withTemporaryApp({ config: { security: { ...TEST_SECURITY, ...LOCKOUT } } }, async (temp) => {
        const email = uniqueEmail('ticket');
        const reg = await post(temp.baseUrl, '/register', { email, password });
        const cookie = ticketCookieOf(reg);
        assert.match(reg.headers.getSetCookie().find((c) => c.startsWith('__Host-verification_ticket=')), /HttpOnly/i);
        const { verificationCode } = lastCode(temp, email);
        await strangerLocks(temp, email, verificationCode);
        const res = await post(temp.baseUrl, '/register/verify-email', { email, code: verificationCode }, { Cookie: cookie });
        assert.equal(res.status, 200);
        assert.ok(res.headers.getSetCookie().some((c) => c.startsWith('__Host-verification_ticket=;')), 'ticket cleared');
        const user = await temp.state.storage.userRepository.findByEmail(email);
        assert.equal(await temp.state.storage.verificationTokenRepository.findActive('verification_ticket', { tokenHash: hashOpaqueToken(temp.state, cookie.split('=')[1], HASH_PURPOSES.EMAIL_VERIFICATION_TICKET) }, user.id), null, 'tickets deleted');
    });
});

test('a ticket has its own budget; a ticket of another account, or a dummy, buys nothing', async () => {
    await withTemporaryApp({ config: { security: { ...TEST_SECURITY, ...LOCKOUT } } }, async (temp) => {
        const victim = uniqueEmail('ticket-victim');
        const { verificationTicket: victimTicket } = await (await post(temp.baseUrl, '/register', { email: victim, password })).json();
        const { verificationCode } = lastCode(temp, victim);
        const wrong = verificationCode === '123456' ? '654321' : '123456';

        // A stranger's tickets: one from their own registration, one (a dummy) from re-registering an active address.
        const { verificationTicket: ownTicket } = await (await post(temp.baseUrl, '/register', { email: uniqueEmail('ticket-attacker'), password })).json();
        const active = await registered(temp);
        const { verificationTicket: dummy } = await (await post(temp.baseUrl, '/register', { email: active, password })).json();
        for (const ticket of [ownTicket, dummy, ownTicket]) await post(temp.baseUrl, '/register/verify-email', { email: victim, code: wrong, ticket });
        assert.equal((await post(temp.baseUrl, '/register/verify-email', { email: victim, code: verificationCode })).status, 429, 'those attempts spent the shared budget');

        // The victim's ticket: three wrong guesses lock it too — its own budget is bounded.
        for (let i = 0; i < 3; i += 1) await post(temp.baseUrl, '/register/verify-email', { email: victim, code: wrong, ticket: victimTicket });
        assert.equal((await post(temp.baseUrl, '/register/verify-email', { email: victim, code: verificationCode, ticket: victimTicket })).status, 429);
        // ...and the link still works.
        assert.equal((await post(temp.baseUrl, '/register/verify-email', { email: victim, token: lastCode(temp, victim).verificationToken })).status, 200);
    });
});

test('at most 5 real tickets per account and code lifetime — more requests get dummies', async () => {
    await withTemporaryApp({ config: { security: { ...TEST_SECURITY, ...LOCKOUT } } }, async (temp) => {
        const email = uniqueEmail('ticket-quota');
        const tickets = [(await (await post(temp.baseUrl, '/register', { email, password })).json()).verificationTicket];
        for (let i = 1; i <= 5; i += 1) {
            tickets.push((await (await post(temp.baseUrl, '/register/resend-verification', { email })).json()).verificationTicket);
            await waitForHookCall(temp, 'onVerificationEmailRequested', (c) => c.email === email, { count: i + 1 });
        }
        const { verificationCode } = lastCode(temp, email);
        await strangerLocks(temp, email, verificationCode);
        assert.equal((await post(temp.baseUrl, '/register/verify-email', { email, code: verificationCode, ticket: tickets[5] })).status, 429, 'the 6th ticket is a dummy');
        assert.equal((await post(temp.baseUrl, '/register/verify-email', { email, code: verificationCode, ticket: tickets[4] })).status, 200, 'the 5th is real');
    });
});
