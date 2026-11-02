import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { buildTestApp, withTemporaryApp, uniqueEmail, waitForHookCall, TEST_SECURITY } from './helpers/build-test-app.js';
import { json } from './helpers/serve.js';
import { gate } from './helpers/gate.js';
import { authorizeCode, exchangeCode, pkcePair } from './helpers/oauth.js';
import { generate as generateTotp } from 'otplib';

// Findings of the second (races / protocol / data) review. Interleavings are forced with gate().

const attackerPassword = 'Att4cker!Passw0rd';
const victimPassword = 'V1ctim!Passw0rd';
let app;

before(async () => {
    app = await buildTestApp();
});

after(async () => {
    await app.stop();
});

const post = (path, body, headers, base = app.baseUrl) => fetch(`${base}${path}`, json(body, headers));
const lastCode = (email, a = app) => a.hookCalls.onVerificationEmailRequested.filter((c) => c.email === email).at(-1);
const users = () => app.state.storage.userRepository;
const rows = (filter) => app.state.storage.connection.model('IdpVerificationToken').find(filter).lean();

async function magicLinkToken(email) {
    await post('/magic-link/request', { email });
    return app.hookCalls.onMagicLinkRequested.filter((c) => c.email === email).at(-1).magicLinkToken;
}

// ── Pre-account takeover ─────────────────────────────────────────────────────

test('a password reset on a never-verified account activates it, so the pre-registration code cannot later activate the attacker\'s password', async () => {
    const email = uniqueEmail('reset-pending');
    await post('/register', { email, password: attackerPassword }); // the attacker's pre-registration
    const { verificationCode, verificationToken } = lastCode(email);

    // The victim can't sign in, so resets the password from their inbox.
    await post('/password/forgot', { email });
    const { resetToken } = await waitForHookCall(app, 'onPasswordResetRequested', (c) => c.email === email);
    assert.equal((await post('/password/reset', { email, token: resetToken, newPassword: victimPassword })).status, 200);
    assert.equal((await post('/login', { email, password: victimPassword })).status, 200, 'the reset activated the account');

    // The registration email's code and link no longer do anything.
    assert.equal((await post('/register/verify-email', { email, code: verificationCode })).status, 400);
    assert.equal((await post('/register/verify-email', { email, token: verificationToken })).status, 400);
    assert.equal((await post('/login', { email, password: attackerPassword })).status, 401);
    assert.equal((await post('/login', { email, password: victimPassword })).status, 200);
});

test('a re-registration that read the account as pending cannot overwrite it once a magic link activated it', async () => {
    const email = uniqueEmail('race-ml');
    await post('/register', { email, password: attackerPassword });
    const token = await magicLinkToken(email);

    // The attacker's second registration reads PENDING and is held there...
    const g = gate(users(), 'findByEmail', { pred: (e) => e === email });
    const register = post('/register', { email, password: attackerPassword });
    await g.reached;
    g.restore();
    // ...while the owner signs in by magic link (activating the account, passwordless).
    assert.equal((await post('/magic-link/verify', { token })).status, 200);
    g.release();
    assert.equal((await register).status, 201);

    assert.equal((await post('/login', { email, password: attackerPassword })).status, 401, 'no attacker password on the live account');
});

test('a re-registration that read the account as pending cannot overwrite it once the owner verified', async () => {
    const email = uniqueEmail('race-verify');
    await post('/register', { email, password: victimPassword });
    const victimsCode = lastCode(email).verificationCode;

    const g = gate(users(), 'findByEmail', { pred: (e) => e === email });
    const register = post('/register', { email, password: attackerPassword });
    await g.reached;
    g.restore();
    assert.equal((await post('/register/verify-email', { email, code: victimsCode })).status, 200);
    g.release();
    await register;

    assert.equal((await post('/login', { email, password: attackerPassword })).status, 401);
    assert.equal((await post('/login', { email, password: victimPassword })).status, 200);
});

// ── Verification-code budget ─────────────────────────────────────────────────

test('wrong codes from a stranger lock code attempts without a ticket, not the owner\'s link; the lock looks the same for every address', async () => {
    await withTemporaryApp({ config: { security: { ...TEST_SECURITY, verificationCodeLockout: { maxFailedAttempts: 3, windowSeconds: 60, lockSeconds: 60 } } } }, async (temp) => {
        const p = (path, body) => post(path, body, {}, temp.baseUrl);
        const burn = async (email) => {
            const answers = [];
            for (let i = 0; i < 4; i += 1) {
                const res = await p('/register/verify-email', { email, code: String(100000 + i) });
                answers.push({ status: res.status, body: await res.json() });
            }
            return answers;
        };

        const pending = uniqueEmail('burn-pending');
        await p('/register', { email: pending, password: victimPassword });
        const { verificationCode, verificationToken } = lastCode(pending, temp);

        const pendingAnswers = await burn(pending);
        const unknownAnswers = await burn(uniqueEmail('burn-unknown'));
        assert.deepEqual(pendingAnswers, unknownAnswers, 'a pending registration is indistinguishable from an unknown address');
        assert.equal(pendingAnswers.at(-1).status, 429);

        assert.equal((await p('/register/verify-email', { email: pending, code: verificationCode })).status, 429, 'codes are locked');
        assert.equal((await p('/register/verify-email', { email: pending, token: verificationToken })).status, 200, 'the emailed link still works');
    });
});

test('a right code with a wrong password (contested registration) is never consumed, so nothing has to be put back', async () => {
    const email = uniqueEmail('no-putback');
    await post('/register', { email, password: victimPassword });
    await post('/register', { email, password: attackerPassword }); // contested
    const { verificationCode } = lastCode(email);
    const before = await rows({ kind: 'email_verification' });
    assert.equal((await post('/register/verify-email', { email, code: verificationCode, password: victimPassword })).status, 400);
    const afterRows = await rows({ kind: 'email_verification' });
    assert.deepEqual(afterRows.map((r) => String(r._id)).sort(), before.map((r) => String(r._id)).sort(), 'same rows — none consumed and re-created');
});

// ── One live link per user ───────────────────────────────────────────────────

test('concurrent forgot-password and magic-link requests leave exactly one live link each', async () => {
    const email = uniqueEmail('one-link');
    await post('/register', { email, password: victimPassword });
    assert.equal((await post('/register/verify-email', { email, code: lastCode(email).verificationCode })).status, 200);
    const user = await users().findByEmail(email);

    await Promise.all(Array.from({ length: 6 }, () => post('/password/forgot', { email })));
    await waitForHookCall(app, 'onPasswordResetRequested', (c) => c.email === email, { count: 6 });
    await Promise.all(Array.from({ length: 6 }, () => post('/magic-link/request', { email })));

    assert.equal((await rows({ kind: 'password_reset', user: user.id, usedAt: null })).length, 1);
    assert.equal((await rows({ kind: 'magic_link', user: user.id })).length, 1);
});

// ── Sessions and tokens that outlive a revocation they raced ─────────────────

const password = 'Str0ng!Passw0rd';
const redirectUri = 'https://rp.example.com/cb';
const ADMIN = { 'x-test-admin': 'yes' };
const bearer = (t) => ({ Authorization: `Bearer ${t}` });

async function activeUser(a = app) {
    const email = uniqueEmail('race-u');
    await post('/register', { email, password }, {}, a.baseUrl);
    await post('/register/verify-email', { email, code: lastCode(email, a).verificationCode }, {}, a.baseUrl);
    const login = await (await post('/login', { email, password }, {}, a.baseUrl)).json();
    assert.ok(login.accessToken, JSON.stringify(login));
    return { email, ...login };
}

async function oauthClient() {
    const c = await (await post('/oauth2/clients', {
        name: 'RP', slug: `race-${Date.now()}-${Math.random().toString(36).slice(2)}`, redirectUris: [redirectUri],
        allowedScopes: ['openid', 'email'], allowedGrants: ['authorization_code', 'refresh_token'],
    }, ADMIN)).json();
    await fetch(`${app.baseUrl}/oauth2/clients/${c.clientId}/approve`, { method: 'POST', headers: ADMIN });
    return c;
}

test('an /oauth2/authorize request in flight across "sign out everywhere" yields a code that does not redeem', async () => {
    const u = await activeUser();
    const c = await oauthClient();
    await authorizeCode({ baseUrl: app.baseUrl, accessToken: u.accessToken, clientId: c.clientId, redirectUri }); // consent exists now

    const pkce = pkcePair();
    const qs = new URLSearchParams({ client_id: c.clientId, redirect_uri: redirectUri, response_type: 'code', scope: 'openid', code_challenge: pkce.challenge, code_challenge_method: 'S256' });
    const g = gate(app.state.storage.consentRepository, 'find');
    const authorize = fetch(`${app.baseUrl}/oauth2/authorize?${qs}`, { headers: bearer(u.accessToken), redirect: 'manual' });
    await g.reached;
    g.restore();
    assert.equal((await fetch(`${app.baseUrl}/logout/all`, { method: 'POST', headers: bearer(u.accessToken) })).status, 200);
    g.release();
    const res = await authorize;
    assert.equal(res.status, 302);
    const code = new URL(res.headers.get('location')).searchParams.get('code');

    const late = await exchangeCode({ baseUrl: app.baseUrl, client: c, code, redirectUri, verifier: pkce.verifier });
    assert.equal(late.status, 400, JSON.stringify(late.body));
});

test('a code replayed while its first redemption is in flight ends the winner tokens too', async () => {
    const u = await activeUser();
    const c = await oauthClient();
    const { code, verifier } = await authorizeCode({ baseUrl: app.baseUrl, accessToken: u.accessToken, clientId: c.clientId, redirectUri });

    const g = gate(app.state.storage.sessionRepository, 'createSession', { when: 'before', pred: (row) => row.kind === 'oauth2' });
    const first = exchangeCode({ baseUrl: app.baseUrl, client: c, code, redirectUri, verifier });
    await g.reached;
    g.restore();
    assert.equal((await exchangeCode({ baseUrl: app.baseUrl, client: c, code, redirectUri, verifier })).status, 400, 'the replay');
    g.release();
    const winner = await first;
    if (winner.status === 200) {
        const r = await post('/oauth2/token', { grant_type: 'refresh_token', refresh_token: winner.body.refresh_token, client_id: c.clientId, client_secret: c.clientSecret });
        assert.equal(r.status, 400, 'the winner refresh token was revoked with the family');
    } else {
        assert.equal(winner.status, 400);
    }
});

test('a refresh in flight when reuse detection revokes its family does not keep a successor', async () => {
    await withTemporaryApp({ config: { session: { refreshReuseGraceSeconds: 0 } } }, async (temp) => {
        const p = (path, body, headers) => post(path, body, headers, temp.baseUrl);
        const u = await activeUser(temp);
        const r1 = (await (await p('/refresh', { refreshToken: u.refreshToken })).json()).refreshToken;

        const g = gate(temp.state.storage.sessionRepository, 'createSession', { when: 'before' });
        const inFlight = p('/refresh', { refreshToken: r1 });
        await g.reached;
        g.restore();
        assert.equal((await p('/refresh', { refreshToken: u.refreshToken })).status, 401, 'replay of the rotated token: reuse detected');
        g.release();
        const res = await inFlight;
        assert.equal(res.status, 401, 'the successor written after the family was revoked is refused');
    });
});

test('a password login in flight across a password reset does not keep a session', async () => {
    const u = await activeUser();
    const g = gate(app.state.storage.sessionRepository, 'createSessionForLogin', { when: 'before' });
    const login = post('/login', { email: u.email, password });
    await g.reached;
    g.restore();
    await post('/password/forgot', { email: u.email });
    const { resetToken } = await waitForHookCall(app, 'onPasswordResetRequested', (x) => x.email === u.email);
    assert.equal((await post('/password/reset', { email: u.email, token: resetToken, newPassword: 'N3w!Passw0rd' })).status, 200);
    g.release();
    const res = await login;
    assert.equal(res.status, 401);
    assert.equal((await res.json()).error, 'TOKEN_REVOKED');
});

test('a refresh in flight across MFA enrolment does not keep the other (pre-MFA) session; the enrolling one continues', async () => {
    const u = await activeUser();
    const other = await (await post('/login', { email: u.email, password })).json();

    const g = gate(app.state.storage.sessionRepository, 'createSession', { when: 'before' });
    const inFlight = post('/refresh', { refreshToken: other.refreshToken });
    await g.reached;
    g.restore();
    const { secret } = await (await fetch(`${app.baseUrl}/me/mfa/setup`, { method: 'POST', headers: bearer(u.accessToken) })).json();
    assert.equal((await post('/me/mfa/confirm', { code: await generateTotp({ secret }) }, bearer(u.accessToken))).status, 200);
    g.release();

    assert.equal((await inFlight).status, 401, 'the other session in-flight refresh is refused');
    assert.equal((await post('/refresh', { refreshToken: u.refreshToken })).status, 200, 'the enrolling session refreshes');
});

test('signing in another way does not reset the password-login budget', async () => {
    const u = await activeUser();
    for (let i = 0; i < app.state.config.security.maxFailedLoginAttempts; i += 1) await post('/login', { email: u.email, password: 'Wr0ng!Passw0rd' });
    assert.equal((await post('/magic-link/verify', { token: await magicLinkToken(u.email) })).status, 200);
    assert.equal((await post('/login', { email: u.email, password })).status, 401, 'password login is still locked');
});

test('a concurrent burst of wrong passwords raises one lock and leaves password login locked', async () => {
    const u = await activeUser();
    const alerts = () => app.hookCalls.onSuspiciousActivityDetected.filter((x) => x.userId === u.userId).length;
    await Promise.all(Array.from({ length: 25 }, () => post('/login', { email: u.email, password: 'Wr0ng!Passw0rd' })));
    assert.equal(alerts(), 1, 'one lock, raised once');
    assert.equal((await post('/login', { email: u.email, password })).status, 401);
});

test('password login fails closed when the attempt-counter backend is down (no session issued)', async () => {
    const u = await activeUser();
    const saved = app.state.attemptCounters;
    app.state.attemptCounters = { get: async () => { throw new Error('db down'); }, recordFailure: async () => { throw new Error('db down'); }, reset: async () => {} };
    try {
        const res = await post('/login', { email: u.email, password });
        assert.equal(res.status, 500);
        assert.equal((await res.json()).accessToken, undefined);
    } finally {
        app.state.attemptCounters = saved;
    }
});
