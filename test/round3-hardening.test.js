import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import { buildTestApp, withTemporaryApp, uniqueEmail } from './helpers/build-test-app.js';
import { json } from './helpers/serve.js';
import { gate } from './helpers/gate.js';
import { authorizeCode, exchangeCode } from './helpers/oauth.js';
import { issueAccessToken } from '../src/index.js';

// Findings of the verification review of the round-2 fixes.

const SHARED = 'shared-bootstrap-secret-round3-0123456789';
const ADMIN = { 'x-test-admin': 'yes' };
const password = 'Str0ng!Passw0rd';
const redirectUri = 'https://rp.example.com/cb';
let app;

before(async () => {
    app = await buildTestApp({ config: { serviceMesh: { bootstrapSecret: SHARED, ownServiceName: 'idp' } } });
});

after(async () => {
    await app.stop();
});

const post = (path, body, headers) => fetch(`${app.baseUrl}${path}`, json(body, headers));
const bearer = (t) => ({ Authorization: `Bearer ${t}` });

async function user() {
    const email = uniqueEmail('r3');
    await post('/register', { email, password });
    await post('/register/verify-email', { email, code: app.hookCalls.onVerificationEmailRequested.filter((c) => c.email === email).at(-1).verificationCode });
    return { email, ...(await (await post('/login', { email, password })).json()) };
}

async function client(extra = {}) {
    const c = await (await post('/oauth2/clients', {
        name: 'RP', slug: `r3-${crypto.randomUUID()}`, redirectUris: [redirectUri],
        allowedScopes: ['openid', 'email', 'reports'], allowedGrants: ['authorization_code', 'refresh_token', 'client_credentials'], ...extra,
    }, ADMIN)).json();
    await fetch(`${app.baseUrl}/oauth2/clients/${c.clientId}/approve`, { method: 'POST', headers: ADMIN });
    return c;
}

test('a duplicate session cookie spelled with a space before "=" is still a duplicate', async () => {
    const victim = await user();
    const attacker = await user();
    const res = await fetch(`${app.baseUrl}/session/refresh`, { method: 'POST', headers: { Cookie: `__Secure-refresh_token =${attacker.refreshToken}; __Secure-refresh_token=${victim.refreshToken}` } });
    assert.equal(res.status, 400);
    assert.equal((await res.json()).error, 'COOKIE_CONFLICT');
});

test('concurrent shared-secret first registrations: the one inserted first keeps the name, whatever the app clocks say', async () => {
    const name = `svc-${crypto.randomUUID().slice(0, 8)}`;
    const rsa = () => crypto.generateKeyPairSync('rsa', { modulusLength: 2048, publicKeyEncoding: { type: 'spki', format: 'pem' }, privateKeyEncoding: { type: 'pkcs8', format: 'pem' } }).publicKey;
    const register = (pem) => post('/internal/service-keys', { name, publicKey: Buffer.from(pem).toString('base64') }, { 'x-s2s-bootstrap-secret': SHARED });
    // B starts first but is held right before its insert; A then registers completely.
    const g = gate(app.state.storage.serviceKeyRepository.model, 'findOneAndUpdate', { when: 'before' });
    const b = register(rsa());
    await g.reached;
    g.restore();
    assert.equal((await register(rsa())).status, 201, 'A');
    g.release();
    assert.equal((await b).status, 409, 'B was inserted second, so it yields');
    const live = (await app.state.storage.serviceKeyRepository.listPublishable()).filter((k) => k.name === name);
    assert.equal(live.length, 1);
});

test('a code stays redeemable after an ordinary refresh of the session that authorized it', async () => {
    const u = await user();
    const c = await client();
    const { code, verifier } = await authorizeCode({ baseUrl: app.baseUrl, accessToken: u.accessToken, clientId: c.clientId, redirectUri });
    assert.equal((await post('/session/refresh', { refreshToken: u.refreshToken })).status, 200);
    const res = await exchangeCode({ baseUrl: app.baseUrl, client: c, code, redirectUri, verifier });
    assert.equal(res.status, 200, JSON.stringify(res.body));
});

test('…but not after that session was signed out', async () => {
    const u = await user();
    const c = await client();
    const { code, verifier } = await authorizeCode({ baseUrl: app.baseUrl, accessToken: u.accessToken, clientId: c.clientId, redirectUri });
    const rotated = await (await post('/session/refresh', { refreshToken: u.refreshToken })).json();
    assert.equal((await post('/session/logout', { refreshToken: rotated.refreshToken })).status, 200);
    assert.equal((await exchangeCode({ baseUrl: app.baseUrl, client: c, code, redirectUri, verifier })).status, 400);
});

test('a code authorized with a sessionless token (the issueAccessToken export) redeems', async () => {
    const u = await user();
    const c = await client();
    const { token } = await issueAccessToken({ sub: u.userId, email: u.email, claims: {} });
    const { code, verifier } = await authorizeCode({ baseUrl: app.baseUrl, accessToken: token, clientId: c.clientId, redirectUri });
    assert.equal((await exchangeCode({ baseUrl: app.baseUrl, client: c, code, redirectUri, verifier })).status, 200);
});

test('client token lifetimes stored before the cap are clamped at issuance', async () => {
    const c = await client({ allowedGrants: ['client_credentials'] });
    await app.state.storage.connection.model('IdpOAuthClient').updateOne({ clientId: c.clientId }, { $set: { accessTokenTTL: 10 * 365 * 24 * 3600 } });
    const body = await (await post('/oauth2/token', { grant_type: 'client_credentials', client_id: c.clientId, client_secret: c.clientSecret })).json();
    assert.equal(body.expires_in, 24 * 3600);
});

test('startup accepts harmless variants: sameSite "Lax", an uppercase trusted origin (normalised)', async () => {
    await withTemporaryApp({ config: { cookies: { sameSite: 'Lax', trustedOrigins: ['https://APP.Example.com'] } } }, async (temp) => {
        assert.equal(temp.state.config.cookies.sameSite, 'lax');
        assert.deepEqual(temp.state.config.cookies.trustedOrigins, ['https://app.example.com']);
    });
});

test('wrong passwords against a passwordless account trigger no lock and no "suspicious activity" mail', async () => {
    const email = uniqueEmail('r3-nopw');
    await post('/magic-link/request', { email });
    const token = app.hookCalls.onMagicLinkRequested.filter((c) => c.email === email).at(-1).magicLinkToken;
    const { userId } = await (await post('/magic-link/verify', { token })).json();
    for (let i = 0; i < 8; i += 1) assert.equal((await post('/login', { email, password: 'Wr0ng!Passw0rd' })).status, 401);
    assert.equal(app.hookCalls.onSuspiciousActivityDetected.filter((x) => x.userId === userId).length, 0);
});

test('a password reset that activates a pending account leaves no MFA state behind', async () => {
    await withTemporaryApp({}, async (temp) => {
        const email = uniqueEmail('r3-reset');
        await fetch(`${temp.baseUrl}/register`, json({ email, password }));
        const pending = await temp.state.storage.userRepository.findByEmail(email);
        await temp.state.storage.userRepository.updateById(pending.id, { mfaEnabled: true }); // whatever an earlier state left
        await fetch(`${temp.baseUrl}/password/forgot`, json({ email }));
        const { waitForHookCall } = await import('./helpers/build-test-app.js');
        const { resetToken } = await waitForHookCall(temp, 'onPasswordResetRequested', (c) => c.email === email);
        assert.equal((await fetch(`${temp.baseUrl}/password/reset`, json({ email, token: resetToken, newPassword: 'N3w!Passw0rd' }))).status, 200);
        const after = await temp.state.storage.userRepository.findByEmail(email);
        assert.equal(after.status, 'ACTIVE');
        assert.equal(after.mfaEnabled, false);
    });
});
