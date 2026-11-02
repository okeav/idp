import { test, before, after, mock } from 'node:test';
import assert from 'node:assert/strict';
import { buildTestApp, withTemporaryApp, uniqueEmail } from './helpers/build-test-app.js';
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
        const res = await fetch(`${temp.baseUrl}/oidc/end-session?state=abc&ui_locales=de`, { headers: { Cookie: `__Host-access_token=${u.accessToken}` }, redirect: 'manual' });
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
