import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { buildTestApp, withTemporaryApp, uniqueEmail, waitForHookCall } from './helpers/build-test-app.js';
import { json } from './helpers/serve.js';
import { authorizeCode, exchangeCode } from './helpers/oauth.js';
import { revokeAllUserSessions } from '../src/utils/session-family.js';

// Session-lifecycle issues found in the 0.3.0 audit:
//  - replaying an already-rotated refresh token was just refused — the thief's
//    (or the victim's) chain carried on; reusing an authorization code didn't
//    revoke what its first redemption produced;
//  - sessions never ended while in use (sliding 30 days, forever);
//  - a refresh racing logout-all / password reset could leave a session alive;
//  - the new-device alert could never fire;
//  - a locked account still told right passwords from wrong ones.

const ADMIN = { 'x-test-admin': 'yes' };
const password = 'Str0ng!Passw0rd';
const redirectUri = 'https://client.example.com/callback';
let app;

before(async () => {
    app = await buildTestApp();
});

after(async () => {
    await app.stop();
});

const post = (path, body, headers, base = app.baseUrl) => fetch(`${base}${path}`, json(body, headers));
const bearer = (t) => ({ Authorization: `Bearer ${t}` });
const audits = (action, userId) => app.hookCalls.onAuditLog.filter((e) => e.action === action && (!userId || e.userId === String(userId)));

async function user({ base = app.baseUrl, a = app, ua } = {}) {
    const email = uniqueEmail('fam');
    await post('/register', { email, password }, {}, base);
    const code = a.hookCalls.onVerificationEmailRequested.filter((c) => c.email === email).at(-1).verificationCode;
    await post('/register/verify-email', { email, code }, {}, base);
    return { email, ...(await (await post('/login', { email, password }, ua ? { 'User-Agent': ua } : {}, base)).json()) };
}

async function withSessionConfig(patch, fn) {
    const s = app.state.config.session;
    const saved = { ...s };
    Object.assign(s, patch);
    try {
        await fn();
    } finally {
        Object.assign(s, saved);
    }
}

const refresh = (refreshToken) => post('/refresh', { refreshToken });

test('replaying a rotated refresh token revokes the whole family (theft detection)', async () => {
    await withSessionConfig({ refreshReuseGraceSeconds: 0 }, async () => {
        const u = await user();
        const r2 = await (await refresh(u.refreshToken)).json();
        assert.ok(r2.refreshToken);

        const replay = await refresh(u.refreshToken);
        assert.equal(replay.status, 401);
        assert.equal((await refresh(r2.refreshToken)).status, 401, 'the legitimate successor dies too');
        assert.equal((await fetch(`${app.baseUrl}/me`, { headers: bearer(r2.accessToken) })).status, 401, 'and its access token');
        assert.equal(audits('REFRESH_TOKEN_REUSE_DETECTED', u.userId).length, 1);

        // Other logins of the same user are separate families and survive.
        const other = await (await post('/login', { email: u.email, password })).json();
        assert.equal((await fetch(`${app.baseUrl}/me`, { headers: bearer(other.accessToken) })).status, 200);
    });
});

test('within the reuse grace (two tabs refreshing at once) a replay is only refused', async () => {
    await withSessionConfig({ refreshReuseGraceSeconds: 30 }, async () => {
        const u = await user();
        const r2 = await (await refresh(u.refreshToken)).json();
        assert.equal((await refresh(u.refreshToken)).status, 401);
        assert.equal((await refresh(r2.refreshToken)).status, 200, 'the family survives');
    });
});

test('an OAuth2 refresh-token replay revokes that grant\'s family', async () => {
    await withSessionConfig({ refreshReuseGraceSeconds: 0 }, async () => {
        const u = await user();
        const c = await (await post('/oauth2/clients', { name: 'RP', slug: `rp-${Math.random()}`, redirectUris: [redirectUri], allowedScopes: ['openid'] }, ADMIN)).json();
        await fetch(`${app.baseUrl}/oauth2/clients/${c.clientId}/approve`, { method: 'POST', headers: ADMIN });
        const { code, verifier } = await authorizeCode({ baseUrl: app.baseUrl, accessToken: u.accessToken, clientId: c.clientId, redirectUri });
        const t1 = (await exchangeCode({ baseUrl: app.baseUrl, client: c, code, redirectUri, verifier })).body;
        const grant = (rt) => post('/oauth2/token', { grant_type: 'refresh_token', refresh_token: rt, client_id: c.clientId, client_secret: c.clientSecret });

        const t2 = await (await grant(t1.refresh_token)).json();
        assert.equal((await grant(t1.refresh_token)).status, 400);
        assert.equal((await grant(t2.refresh_token)).status, 400, 'the successor was revoked with the family');
        assert.equal((await fetch(`${app.baseUrl}/userinfo`, { headers: bearer(t2.access_token) })).status, 401);
    });
});

test('redeeming an authorization code twice revokes everything the first redemption produced', async () => {
    const u = await user();
    const c = await (await post('/oauth2/clients', { name: 'RP', slug: `rp-${Math.random()}`, redirectUris: [redirectUri], allowedScopes: ['openid'] }, ADMIN)).json();
    await fetch(`${app.baseUrl}/oauth2/clients/${c.clientId}/approve`, { method: 'POST', headers: ADMIN });
    const { code, verifier } = await authorizeCode({ baseUrl: app.baseUrl, accessToken: u.accessToken, clientId: c.clientId, redirectUri });
    const first = (await exchangeCode({ baseUrl: app.baseUrl, client: c, code, redirectUri, verifier })).body;
    assert.equal((await fetch(`${app.baseUrl}/userinfo`, { headers: bearer(first.access_token) })).status, 200);

    const second = await exchangeCode({ baseUrl: app.baseUrl, client: c, code, redirectUri, verifier });
    assert.equal(second.status, 400);
    assert.equal(second.body.error, 'INVALID_GRANT');
    assert.equal((await fetch(`${app.baseUrl}/userinfo`, { headers: bearer(first.access_token) })).status, 401);
    const refreshed = await post('/oauth2/token', { grant_type: 'refresh_token', refresh_token: first.refresh_token, client_id: c.clientId, client_secret: c.clientSecret });
    assert.equal(refreshed.status, 400);
    assert.equal(audits('OAUTH2_CODE_REUSE_DETECTED', u.userId).length, 1);
});

test('a session family has an absolute lifetime, however actively it is refreshed', async () => {
    await withSessionConfig({ absoluteLifetimeSeconds: 2 }, async () => {
        const u = await user();
        const expiresAt = new Date(u.refreshTokenExpiresAt).getTime();
        assert.ok(expiresAt <= Date.now() + 2500, 'the refresh token itself never outlives the family');

        const r2 = await (await refresh(u.refreshToken)).json();
        await new Promise((r) => setTimeout(r, 2100));
        const late = await refresh(r2.refreshToken);
        assert.equal(late.status, 401);
    });
});

test('a refresh racing logout-all cannot leave a session alive', async () => {
    const u = await user();
    const sessions = app.state.storage.sessionRepository;
    const original = sessions.createSession;
    // Logout-all lands exactly between the refresh consuming its row and inserting the successor.
    sessions.createSession = async function (input) {
        sessions.createSession = original;
        await revokeAllUserSessions(app.state, u.userId);
        return original.call(this, input);
    };
    try {
        const res = await refresh(u.refreshToken);
        assert.equal(res.status, 401);
        assert.equal((await res.json()).error, 'TOKEN_REVOKED');
    } finally {
        sessions.createSession = original;
    }
    const live = await sessions.listActiveForUser(u.userId);
    assert.equal(live.length, 0, 'no session survived');
});

test('the new-device alert fires for a new device, and not for a known one', async () => {
    const chrome = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36';
    const firefox = 'Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0';
    const u = await user({ ua: chrome }); // first-ever login: no alert
    const alerts = () => app.hookCalls.onNewDeviceLogin.filter((p) => p.userId === u.userId).length;
    const wait = () => new Promise((r) => setTimeout(r, 100)); // the notification is fire-and-forget

    await post('/login', { email: u.email, password }, { 'User-Agent': chrome });
    await wait();
    assert.equal(alerts(), 0, 'known device');

    await post('/login', { email: u.email, password }, { 'User-Agent': firefox });
    await wait();
    assert.equal(alerts(), 1, 'new device');

    await post('/login', { email: u.email, password }, { 'User-Agent': firefox });
    await wait();
    assert.equal(alerts(), 1, 'now known');
});

test('a locked account answers the same for the right and a wrong password; a password reset lifts the lock', async () => {
    const u = await user();
    for (let i = 0; i < app.state.config.security.maxFailedLoginAttempts; i += 1) {
        await post('/login', { email: u.email, password: 'Wr0ng!Passw0rd' });
    }
    const right = await post('/login', { email: u.email, password });
    const wrong = await post('/login', { email: u.email, password: 'Wr0ng!Passw0rd' });
    assert.equal(right.status, 401);
    assert.equal(wrong.status, 401);
    assert.deepEqual(await right.json(), await wrong.json());

    await post('/password/forgot', { email: u.email });
    const { resetToken } = await waitForHookCall(app, 'onPasswordResetRequested', (c) => c.email === u.email);
    assert.equal((await post('/password/reset', { email: u.email, token: resetToken, newPassword: 'N3w!Passw0rd' })).status, 200);
    assert.equal((await post('/login', { email: u.email, password: 'N3w!Passw0rd' })).status, 200);
});

test('password reset: a newer link invalidates older ones; deleted accounts get none', async () => {
    const u = await user();
    await post('/password/forgot', { email: u.email });
    const first = (await waitForHookCall(app, 'onPasswordResetRequested', (c) => c.email === u.email)).resetToken;
    await post('/password/forgot', { email: u.email });
    const second = (await waitForHookCall(app, 'onPasswordResetRequested', (c) => c.email === u.email, { count: 2 })).resetToken;
    assert.notEqual(first, second);
    assert.equal((await post('/password/reset', { email: u.email, token: first, newPassword: 'N3w!Passw0rd' })).status, 400);
    assert.equal((await post('/password/reset', { email: u.email, token: second, newPassword: 'N3w!Passw0rd' })).status, 200);

    const gone = await user();
    await app.state.storage.userRepository.updateById(gone.userId, { status: 'DELETED' });
    assert.equal((await post('/password/forgot', { email: gone.email })).status, 200);
    // The request's work runs after the response: let a later request for a live account finish first.
    const live = await user();
    await post('/password/forgot', { email: live.email });
    await waitForHookCall(app, 'onPasswordResetRequested', (c) => c.email === live.email);
    assert.equal(app.hookCalls.onPasswordResetRequested.filter((c) => c.email === gone.email).length, 0);
});

test('password-reset requests are rate limited per address', async () => {
    await withTemporaryApp({ config: { rateLimiting: { enabled: true, passwordReset: { max: 100, windowSeconds: 60 }, passwordResetByEmail: { max: 2, windowSeconds: 60 } } } }, async (temp) => {
        const email = uniqueEmail('reset-flood');
        const f = () => fetch(`${temp.baseUrl}/password/forgot`, json({ email }));
        assert.equal((await f()).status, 200);
        assert.equal((await f()).status, 200);
        assert.equal((await f()).status, 429);
    });
});
