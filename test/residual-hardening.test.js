import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { generate as generateTotp } from 'otplib';
import { buildTestApp, withTemporaryApp, uniqueEmail } from './helpers/build-test-app.js';
import { json } from './helpers/serve.js';
import { authorizeCode } from './helpers/oauth.js';
import { AesGcmSecretCipher, verifyAccessToken } from '../src/index.js';
import { sealMfaSecret } from '../src/mfa/secrets.js';

// The remaining audit items: magic-link inbox flooding and stale links, other
// sessions surviving MFA enrolment, lenient MFA key decoding, a custom cipher
// whose output reads as plain text, 500s on malformed ids/cookies, claims
// frozen at login, and `openid` granted to clients not registered for it.

const ADMIN = { 'x-test-admin': 'yes' };
const password = 'Str0ng!Passw0rd';
let app;

before(async () => {
    app = await buildTestApp();
});

after(async () => {
    await app.stop();
});

const post = (path, body, headers) => fetch(`${app.baseUrl}${path}`, json(body, headers));
const bearer = (t) => ({ Authorization: `Bearer ${t}` });

async function user() {
    const email = uniqueEmail('resid');
    await post('/register', { email, password });
    const code = app.hookCalls.onVerificationEmailRequested.filter((c) => c.email === email).at(-1).verificationCode;
    await post('/register/verify-email', { email, code });
    return { email, ...(await (await post('/login', { email, password })).json()) };
}

test('magic link: a new link invalidates the previous one', async () => {
    const email = uniqueEmail('ml-latest');
    await post('/magic-link/request', { email });
    const first = app.hookCalls.onMagicLinkRequested.filter((c) => c.email === email).at(-1).magicLinkToken;
    await post('/magic-link/request', { email });
    const second = app.hookCalls.onMagicLinkRequested.filter((c) => c.email === email).at(-1).magicLinkToken;
    assert.equal((await post('/magic-link/verify', { token: first })).status, 400);
    assert.equal((await post('/magic-link/verify', { token: second })).status, 200);
});

test('magic link: requests are rate limited per address (no inbox flooding)', async () => {
    await withTemporaryApp({ config: { rateLimiting: { enabled: true, magicLink: { max: 100, windowSeconds: 60 }, magicLinkByEmail: { max: 2, windowSeconds: 60 } } } }, async (temp) => {
        const email = uniqueEmail('ml-flood');
        const r = () => fetch(`${temp.baseUrl}/magic-link/request`, json({ email }));
        assert.equal((await r()).status, 200);
        assert.equal((await r()).status, 200);
        assert.equal((await r()).status, 429);
    });
});

test('enabling MFA signs out the account\'s other sessions, and keeps the current one', async () => {
    const u = await user();
    const other = await (await post('/login', { email: u.email, password })).json(); // e.g. an attacker's session
    const auth = bearer(u.accessToken);
    const { secret } = await (await fetch(`${app.baseUrl}/me/mfa/setup`, { method: 'POST', headers: auth })).json();
    assert.equal((await post('/me/mfa/confirm', { code: await generateTotp({ secret }) }, auth)).status, 200);

    assert.equal((await fetch(`${app.baseUrl}/me`, { headers: bearer(other.accessToken) })).status, 401, 'the other session ended');
    assert.equal((await post('/refresh', { refreshToken: other.refreshToken })).status, 401);
    assert.equal((await fetch(`${app.baseUrl}/me`, { headers: auth })).status, 200, 'the enrolling session continues');
    assert.equal((await post('/refresh', { refreshToken: u.refreshToken })).status, 200);
});

test('MFA encryption keys must be exactly the base64 of 32 bytes — trailing garbage is refused', () => {
    const good = Buffer.alloc(32, 9).toString('base64');
    assert.doesNotThrow(() => new AesGcmSecretCipher({ currentKey: good }));
    assert.doesNotThrow(() => new AesGcmSecretCipher({ currentKey: Buffer.alloc(32, 9).toString('base64url') }));
    assert.throws(() => new AesGcmSecretCipher({ currentKey: `${good}!!garbage` }), /not valid base64/);
    assert.throws(() => new AesGcmSecretCipher({ currentKey: Buffer.alloc(31, 9).toString('base64') }), /32 bytes/);
});

test('a custom secretCipher whose output looks like a plain-text secret is refused', async () => {
    const state = { config: { mfa: {} }, mfaCipher: { encrypt: async (s) => s.toUpperCase(), decrypt: async (s) => s } };
    await assert.rejects(sealMfaSecret(state, 'JBSWY3DPEHPK3PXP', 'u1'), (err) => err.code === 'MFA_SECRET_UNREADABLE');
    state.mfaCipher.encrypt = async (s) => `kms:${s}`;
    assert.equal(await sealMfaSecret(state, 'JBSWY3DPEHPK3PXP', 'u1'), 'kms:JBSWY3DPEHPK3PXP');
});

test('a malformed session id is a 404, and a JSON-typed cookie is no token (both were 500s)', async () => {
    const u = await user();
    const res = await fetch(`${app.baseUrl}/me/sessions/not-an-object-id`, { method: 'DELETE', headers: bearer(u.accessToken) });
    assert.equal(res.status, 404);

    // cookie-parser turns `j:{...}` into an object.
    const jsonCookie = `refresh_token=${encodeURIComponent('j:{"$ne":null}')}`;
    assert.equal((await fetch(`${app.baseUrl}/refresh`, { method: 'POST', headers: { Cookie: jsonCookie } })).status, 400);
    assert.equal((await fetch(`${app.baseUrl}/me`, { headers: { Cookie: `access_token=${encodeURIComponent('j:{"a":1}')}` } })).status, 401);
});

test('by default /refresh re-derives claims, so a role change takes effect within one access-token lifetime', async () => {
    assert.equal(app.state.config.session.reresolveClaimsOnRefresh, true);
    let role = 'admin';
    await withTemporaryApp({ hooks: { resolveAuthContext: async () => ({ claims: { role } }) } }, async (temp) => {
        const email = uniqueEmail('demote');
        await fetch(`${temp.baseUrl}/register`, json({ email, password }));
        const code = temp.hookCalls.onVerificationEmailRequested.filter((c) => c.email === email).at(-1).verificationCode;
        await fetch(`${temp.baseUrl}/register/verify-email`, json({ email, code }));
        const login = await (await fetch(`${temp.baseUrl}/login`, json({ email, password }))).json();
        assert.equal((await verifyAccessToken(login.accessToken)).claims.role, 'admin');

        role = 'member'; // demoted
        const refreshed = await (await fetch(`${temp.baseUrl}/refresh`, json({ refreshToken: login.refreshToken }))).json();
        assert.equal((await verifyAccessToken(refreshed.accessToken)).claims.role, 'member');
    });
});

test('openid is granted only to clients registered for it', async () => {
    const u = await user();
    const res = await post('/oauth2/clients', { name: 'No OIDC', slug: `no-oidc-${Math.random()}`, redirectUris: ['https://client.example.com/cb'], allowedScopes: ['email'] }, ADMIN);
    const c = await res.json();
    await fetch(`${app.baseUrl}/oauth2/clients/${c.clientId}/approve`, { method: 'POST', headers: ADMIN });
    const authorize = await fetch(`${app.baseUrl}/oauth2/authorize?${new URLSearchParams({ client_id: c.clientId, redirect_uri: 'https://client.example.com/cb', response_type: 'code', scope: 'openid email', code_challenge: 'x'.repeat(43), code_challenge_method: 'S256' })}`, { headers: bearer(u.accessToken) });
    assert.equal(authorize.status, 400);
    // …while a scope it is registered for still works.
    const ok = await authorizeCode({ baseUrl: app.baseUrl, accessToken: u.accessToken, clientId: c.clientId, redirectUri: 'https://client.example.com/cb', scope: 'email' });
    assert.ok(ok.code);
});
