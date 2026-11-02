import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import { buildTestApp, withTemporaryApp, uniqueEmail, waitForHookCall } from './helpers/build-test-app.js';
import { json } from './helpers/serve.js';
import { authorizeCode, exchangeCode } from './helpers/oauth.js';
import { revokeServiceKey } from '../src/index.js';
import { localKeyLookup } from '../src/service-mesh/local-key-lookup.js';
import { MemoryRateLimiter } from '../src/rate-limit/memory.adapter.js';
import { dummyHashRounds } from '../src/utils/password.js';

// Findings of the independent review of the 0.4.0 branch:
//  1. five anonymous wrong passwords locked the account out of EVERY method (refresh, magic link,
//     passkey, SSO, OAuth2), burned its refresh token, and a passwordless account stayed locked;
//  2. a pending registration could still be taken over when the victim registered first;
//  3. an authorization code minted before a password reset / consent withdrawal still redeemed;
//  4. a revoked service key came back on the service's next boot; the shared bootstrap secret could
//     claim a per-service name; a rotated-away key verified forever;
//  5. /password/change had no attempt limit;
//  6. the dummy bcrypt hash had a fixed cost (login timing told which emails exist);
//  7. a full in-memory rate limiter answered 503 to every new client;
//  8. login (and the other cookie-setting endpoints) accepted cross-origin form posts — login CSRF;
//  9. (account-takeover.test.js) the stored HMAC of a verification code was accepted as the code;
// 10. forgot-password / resend did their lookups and writes before answering (timing enumeration);
// 11. a refresh that failed after consuming its token burned it (and the retry looked like reuse).

const ADMIN = { 'x-test-admin': 'yes' };
const password = 'Str0ng!Passw0rd';
const redirectUri = 'https://rp.example.com/cb';
const SECRETS = { billing: 'billing-bootstrap-secret-review-01-0123456789', orders: 'orders-bootstrap-secret-review-02-0123456789' };
const SHARED = 'shared-bootstrap-secret-review-03-0123456789';
let app;

before(async () => {
    app = await buildTestApp({ config: { serviceMesh: { bootstrapSecrets: SECRETS, bootstrapSecret: SHARED, ownServiceName: 'idp', rotationGraceSeconds: 1 } } });
});

after(async () => {
    await app.stop();
});

const post = (path, body, headers, base = app.baseUrl) => fetch(`${base}${path}`, json(body, headers));
const bearer = (t) => ({ Authorization: `Bearer ${t}` });
const users = () => app.state.storage.userRepository;

async function user(a = app) {
    const email = uniqueEmail('rv');
    await post('/register', { email, password }, {}, a.baseUrl);
    const code = a.hookCalls.onVerificationEmailRequested.filter((c) => c.email === email).at(-1).verificationCode;
    await post('/register/verify-email', { email, code }, {}, a.baseUrl);
    const login = await (await post('/login', { email, password }, {}, a.baseUrl)).json();
    assert.ok(login.accessToken, JSON.stringify(login));
    return { email, ...login };
}

async function magicLink(email) {
    await post('/magic-link/request', { email });
    const token = app.hookCalls.onMagicLinkRequested.filter((c) => c.email === email).at(-1).magicLinkToken;
    return post('/magic-link/verify', { token });
}

const failLogins = async (email, n = app.state.config.security.maxFailedLoginAttempts) => {
    for (let i = 0; i < n; i += 1) assert.equal((await post('/login', { email, password: 'Wr0ng!Passw0rd' })).status, 401);
};

// ── 1. The password lockout locks password login only ─────────────────────────

test('five wrong passwords lock PASSWORD login only — the account, its sessions and other methods keep working', async () => {
    const u = await user();
    await failLogins(u.email);

    assert.equal((await post('/login', { email: u.email, password })).status, 401, 'password login is locked');
    const stored = await users().findByEmail(u.email);
    assert.equal(stored.status, 'ACTIVE', 'the lock is not an account status');
    assert.equal(stored.lockUntil, null, 'nor written on the account — it lives in the password-login attempt budget');

    assert.equal((await fetch(`${app.baseUrl}/me`, { headers: bearer(u.accessToken) })).status, 200, 'the session lives on');
    const refreshed = await post('/session/refresh', { refreshToken: u.refreshToken });
    assert.equal(refreshed.status, 200, 'and still refreshes');
    assert.equal((await magicLink(u.email)).status, 200, 'and the inbox can still sign in');
});

test('an account without a password is never counted or locked by password attempts', async () => {
    const email = uniqueEmail('rv-nopw');
    assert.equal((await magicLink(email)).status, 200); // signs up by magic link — no password
    await failLogins(email, 8);
    const stored = await users().findByEmail(email);
    assert.equal(stored.lockUntil, null);
    assert.equal(stored.failedLoginAttempts ?? 0, 0);
    assert.equal((await magicLink(email)).status, 200);
});

test('a row locked before 0.4.0 (status LOCKED + lockUntil) is treated as a password lock; once expired, it clears', async () => {
    const u = await user();
    const stored = await users().findByEmail(u.email);
    await users().updateById(stored.id, { status: 'LOCKED', lockUntil: new Date(Date.now() + 60_000) });
    assert.equal((await post('/session/refresh', { refreshToken: u.refreshToken })).status, 200);
    assert.equal((await magicLink(u.email)).status, 200);
    // That sign-in cleared lockUntil — and the legacy status with it (else it would read as an admin lock).
    assert.equal((await users().findByEmail(u.email)).status, 'ACTIVE');

    // An expired legacy lock.
    await users().updateById(stored.id, { status: 'LOCKED', lockUntil: new Date(Date.now() - 1000) });
    assert.equal((await post('/login', { email: u.email, password })).status, 200);
    assert.equal((await users().findByEmail(u.email)).status, 'ACTIVE');
});

test('an administrative lock (status LOCKED, no lockUntil) still blocks every method, and a password reset does not lift it', async () => {
    const u = await user();
    const stored = await users().findByEmail(u.email);
    await users().updateById(stored.id, { status: 'LOCKED', lockUntil: null });

    assert.equal((await post('/session/refresh', { refreshToken: u.refreshToken })).status, 403);
    assert.equal((await magicLink(u.email)).status, 423);
    await post('/password/forgot', { email: u.email });
    const { resetToken } = await waitForHookCall(app, 'onPasswordResetRequested', (c) => c.email === u.email);
    assert.equal((await post('/password/reset', { email: u.email, token: resetToken, newPassword: 'N3w!Passw0rd' })).status, 200);
    assert.equal((await users().findByEmail(u.email)).status, 'LOCKED');
});

// ── 11. A refused or failed refresh does not burn the token ──────────────────

test('a refresh refused for an inactive account does not burn the token', async () => {
    const u = await user();
    const stored = await users().findByEmail(u.email);
    await users().updateById(stored.id, { status: 'SUSPENDED' });
    assert.equal((await post('/session/refresh', { refreshToken: u.refreshToken })).status, 403);
    await users().updateById(stored.id, { status: 'ACTIVE' });
    assert.equal((await post('/session/refresh', { refreshToken: u.refreshToken })).status, 200);
});

test('a refresh whose claims hook throws does not burn the token; the retry succeeds', async () => {
    let failNext = false;
    await withTemporaryApp({ hooks: { resolveAuthContext: async (_u, ctx) => {
        if (ctx.method === 'refresh' && failNext) { failNext = false; throw new Error('claims store unavailable'); }
        return { claims: {} };
    } } }, async (temp) => {
        const u = await user(temp);
        failNext = true;
        assert.equal((await post('/session/refresh', { refreshToken: u.refreshToken }, {}, temp.baseUrl)).status, 500);
        const retry = await post('/session/refresh', { refreshToken: u.refreshToken }, {}, temp.baseUrl);
        assert.equal(retry.status, 200, await retry.clone().text());
        assert.ok(!temp.hookCalls.onAuditLog.some((e) => e.action === 'REFRESH_TOKEN_REUSE_DETECTED'));
    });
});

// ── 3. Unredeemed authorization codes die with the sessions / the consent ────

async function oauthClient() {
    const res = await post('/oauth2/clients', {
        name: 'RP', slug: `rv-${crypto.randomUUID()}`, redirectUris: [redirectUri],
        allowedScopes: ['openid', 'email'], allowedGrants: ['authorization_code', 'refresh_token'],
    }, ADMIN);
    const c = await res.json();
    await fetch(`${app.baseUrl}/oauth2/clients/${c.clientId}/approve`, { method: 'POST', headers: ADMIN });
    return c;
}

test('an authorization code issued before a password reset cannot be redeemed after it', async () => {
    const u = await user();
    const c = await oauthClient();
    const { code, verifier } = await authorizeCode({ baseUrl: app.baseUrl, accessToken: u.accessToken, clientId: c.clientId, redirectUri });

    await post('/password/forgot', { email: u.email });
    const { resetToken } = await waitForHookCall(app, 'onPasswordResetRequested', (x) => x.email === u.email);
    assert.equal((await post('/password/reset', { email: u.email, token: resetToken, newPassword: 'N3w!Passw0rd' })).status, 200);

    const late = await exchangeCode({ baseUrl: app.baseUrl, client: c, code, redirectUri, verifier });
    assert.equal(late.status, 400);
    assert.equal(late.body.error, 'INVALID_GRANT');
});

test('an authorization code issued before consent was withdrawn cannot be redeemed, even after consenting again', async () => {
    const u = await user();
    const c = await oauthClient();
    const before = await authorizeCode({ baseUrl: app.baseUrl, accessToken: u.accessToken, clientId: c.clientId, redirectUri });
    assert.equal((await fetch(`${app.baseUrl}/oauth2/consent/sessions/${c.clientId}`, { method: 'DELETE', headers: bearer(u.accessToken) })).status, 200);
    assert.equal((await exchangeCode({ baseUrl: app.baseUrl, client: c, code: before.code, redirectUri, verifier: before.verifier })).status, 400);

    const again = await authorizeCode({ baseUrl: app.baseUrl, accessToken: u.accessToken, clientId: c.clientId, redirectUri });
    assert.equal((await exchangeCode({ baseUrl: app.baseUrl, client: c, code: again.code, redirectUri, verifier: again.verifier })).status, 200, 'a code from the new consent works');
});

// ── 4. Service keys ──────────────────────────────────────────────────────────

const rsa = () => crypto.generateKeyPairSync('rsa', { modulusLength: 2048, publicKeyEncoding: { type: 'spki', format: 'pem' }, privateKeyEncoding: { type: 'pkcs8', format: 'pem' } });
const registerKey = (name, publicKeyPem, secret) => post('/internal/service-keys', { name, publicKey: Buffer.from(publicKeyPem).toString('base64') }, { 'x-s2s-bootstrap-secret': secret });
const jwks = async () => (await (await fetch(`${app.baseUrl}/.well-known/services-jwks.json`)).json()).keys;

test('a revoked service key is never re-activated by the service re-registering it (e.g. at boot)', async () => {
    const k1 = rsa();
    const kid1 = (await (await registerKey('billing', k1.publicKey, SECRETS.billing)).json()).kid;
    assert.equal(await revokeServiceKey(kid1), true);

    const again = await registerKey('billing', k1.publicKey, SECRETS.billing);
    assert.equal(again.status, 409);
    assert.equal((await again.json()).error, 'SERVICE_KEY_REVOKED');
    assert.ok(!(await jwks()).some((k) => k.kid === kid1));

    // A new key is fine — and a later attempt with the revoked one does not demote it.
    const kid2 = (await (await registerKey('billing', rsa().publicKey, SECRETS.billing)).json()).kid;
    assert.equal((await registerKey('billing', k1.publicKey, SECRETS.billing)).status, 409);
    assert.equal((await jwks()).find((k) => k.kid === kid2)?.status, 'ACTIVE');
});

test('the shared bootstrap secret cannot register a name that has its own per-service secret', async () => {
    const res = await registerKey('orders', rsa().publicKey, SHARED); // orders has never registered
    assert.equal(res.status, 403);
    assert.equal((await registerKey('orders', rsa().publicKey, SECRETS.orders)).status, 201);
});

test('a rotated-away key verifies only for rotationGraceSeconds', async () => {
    const old = (await (await registerKey('orders', rsa().publicKey, SECRETS.orders)).json()).kid;
    await registerKey('orders', rsa().publicKey, SECRETS.orders); // rotation: `old` becomes ROTATING
    const lookup = localKeyLookup(app.state.storage.serviceKeyRepository, { rotationGraceSeconds: 1 });
    assert.equal((await jwks()).find((k) => k.kid === old)?.status, 'ROTATING');
    assert.ok(await lookup(old), 'still verifies right after the rotation');

    await new Promise((r) => setTimeout(r, 1200));
    assert.equal(await lookup(old), null, 'no longer verifies after the grace period');
    assert.ok(!(await jwks()).some((k) => k.kid === old), 'nor is it published');
});

// ── 5. /password/change has an attempt budget ────────────────────────────────

test('/password/change locks after a few wrong current passwords — even the right one is then refused', async () => {
    const u = await user();
    const change = (currentPassword) => post('/password/change', { currentPassword, newPassword: 'N3w!Passw0rd' }, bearer(u.accessToken));
    const max = app.state.config.security.passwordChangeLockout.maxFailedAttempts;
    for (let i = 1; i < max; i += 1) assert.equal((await change(`Guess!${i}aA`)).status, 400);
    const exhausting = await change('Guess!lastaA');
    assert.equal(exhausting.status, 429);
    assert.equal((await exhausting.json()).error, 'PASSWORD_CHANGE_LOCKED');
    assert.equal((await change(password)).status, 429);
});

test('/password/change: a few typos short of the budget do not stop the owner', async () => {
    const u = await user();
    const change = (currentPassword) => post('/password/change', { currentPassword, newPassword: 'N3w!Passw0rd' }, bearer(u.accessToken));
    const max = app.state.config.security.passwordChangeLockout.maxFailedAttempts;
    for (let i = 1; i < max; i += 1) assert.equal((await change(`Typo!${i}aA`)).status, 400);
    assert.equal((await change(password)).status, 200);
});

// ── 6. The dummy hash matches the configured cost ────────────────────────────

test('the dummy password hash uses the configured bcrypt cost', () => {
    assert.equal(dummyHashRounds(), app.state.config.security.bcryptRounds);
});

// ── 7. A full in-memory limiter evicts unexhausted counters ──────────────────

test('a full MemoryRateLimiter makes room by evicting counters below their limit, never exhausted ones', async () => {
    const limiter = new MemoryRateLimiter({ maxKeys: 10 });
    try {
        const rule = { max: 3, windowSeconds: 60 };
        for (let i = 0; i < 3; i += 1) await limiter.increment('blocked', rule); // exhausted
        for (let i = 0; i < 9; i += 1) await limiter.increment(`flood-${i}`, rule);
        // Full. A new client is still served...
        assert.equal((await limiter.increment('new-client', rule)).allowed, true);
        // ...and the exhausted counter survived the eviction.
        assert.equal((await limiter.increment('blocked', rule)).allowed, false);
    } finally {
        limiter.close();
    }

    const allBlocked = new MemoryRateLimiter({ maxKeys: 2 });
    try {
        const rule = { max: 1, windowSeconds: 60 };
        await allBlocked.increment('a', rule);
        await allBlocked.increment('b', rule);
        await assert.rejects(allBlocked.increment('c', rule), /full/);
    } finally {
        allBlocked.close();
    }
});

// ── 8. Login CSRF ────────────────────────────────────────────────────────────

test('endpoints that set session cookies refuse a cross-origin browser request (login CSRF)', async () => {
    const u = await user();
    const evil = { Origin: 'https://evil.sibling.example', 'Sec-Fetch-Site': 'same-site' };
    const form = (headers) => fetch(`${app.baseUrl}/login`, {
        method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', ...headers },
        body: new URLSearchParams({ email: u.email, password }).toString(),
    });
    const forged = await form(evil);
    assert.equal(forged.status, 403);
    assert.equal((await forged.json()).error, 'CSRF_ORIGIN_REJECTED');
    assert.equal(forged.headers.getSetCookie().length, 0);

    assert.equal((await post('/login', { email: u.email, password }, { Origin: new URL(app.state.config.issuer).origin })).status, 200, 'the issuer origin');
    assert.equal((await post('/login', { email: u.email, password })).status, 200, 'a non-browser client');

    // /refresh with a body token: the attacker's own token would sign the victim in as the attacker.
    assert.equal((await post('/session/refresh', { refreshToken: u.refreshToken }, evil)).status, 403);
    assert.equal((await post('/session/refresh', { refreshToken: u.refreshToken })).status, 200, 'the refused request did not consume the token');

    await post('/magic-link/request', { email: u.email });
    const token = app.hookCalls.onMagicLinkRequested.filter((c) => c.email === u.email).at(-1).magicLinkToken;
    assert.equal((await post('/magic-link/verify', { token }, evil)).status, 403);
    assert.equal((await post('/mfa/verify', { mfaChallengeToken: 'x', code: '123456' }, evil)).status, 403);
});

// ── 10. "Send me an email" endpoints answer before looking anything up ───────

test('forgot-password and resend-verification answer before the account lookup (no timing difference)', async () => {
    const u = await user();
    const repo = users();
    const original = repo.findByEmail;
    let released;
    const gate = new Promise((r) => { released = r; });
    repo.findByEmail = async (...args) => { await gate; return original.apply(repo, args); };
    try {
        for (const path of ['/password/forgot', '/register/resend-verification']) {
            const started = Date.now();
            assert.equal((await post(path, { email: u.email })).status, 200);
            assert.ok(Date.now() - started < 1000, `${path} waited for the lookup`);
        }
    } finally {
        released();
        repo.findByEmail = original;
    }
    // The work still happens.
    await waitForHookCall(app, 'onPasswordResetRequested', (c) => c.email === u.email);
});
