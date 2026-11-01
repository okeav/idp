import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import jwt from 'jsonwebtoken';
import { buildTestApp, uniqueEmail } from './helpers/build-test-app.js';
import { json } from './helpers/serve.js';
import { verifyAccessToken, issueAccessToken, authContextMiddleware, tokenHandler } from '../src/index.js';
import { getActiveSigningKey } from '../src/signing/key-registry.js';
import { sessionKindOf } from '../src/utils/session-kind.js';

// Issue: verifyAccessToken/authContextMiddleware never checked WHO a token was
// issued to. An access token minted for a third-party OAuth2 client (aud = that
// client) carried type 'access_token' and a live session row, so it worked as a
// full first-party credential on the IdP's own routes — a relying party the
// user authorized for just `openid` could delete the account, register its own
// passkey, or grant itself consent. Refresh tokens were likewise interchangeable
// between /refresh and /oauth2/token, and between clients.

let app;
const ADMIN = { 'x-test-admin': 'yes' };
const password = 'Str0ng!Passw0rd';
const redirectUri = 'https://client.example.com/callback';

before(async () => {
    app = await buildTestApp();
});

after(async () => {
    await app.stop();
});

async function registerVerifyLogin(email = uniqueEmail('aud')) {
    await fetch(`${app.baseUrl}/register`, json({ email, password }));
    const code = app.hookCalls.onVerificationEmailRequested.find((c) => c.email === email).verificationCode;
    await fetch(`${app.baseUrl}/register/verify-email`, json({ email, code }));
    const body = await (await fetch(`${app.baseUrl}/login`, json({ email, password }))).json();
    return { email, ...body };
}

async function createClient(overrides = {}) {
    const res = await fetch(`${app.baseUrl}/oauth2/clients`, json({
        name: 'RP', slug: `rp-${Date.now()}-${Math.random().toString(36).slice(2)}`, redirectUris: [redirectUri],
        allowedScopes: ['openid', 'email', 'profile'], allowedGrants: ['authorization_code', 'refresh_token', 'client_credentials'],
        ...overrides,
    }, ADMIN));
    const client = await res.json();
    assert.equal(res.status, 201, JSON.stringify(client));
    await fetch(`${app.baseUrl}/oauth2/clients/${client.clientId}/approve`, { method: 'POST', headers: ADMIN });
    return client;
}

/** Runs the full authorization-code flow for `user` and returns the client's token response. */
async function oauthTokensFor(user, client, scope = 'openid') {
    const confirm = await fetch(`${app.baseUrl}/oauth2/authorize/confirm`, {
        ...json({ client_id: client.clientId, redirect_uri: redirectUri, scope }, { Authorization: `Bearer ${user.accessToken}` }),
        redirect: 'manual',
    });
    assert.equal(confirm.status, 302, await confirm.text());
    const code = new URL(confirm.headers.get('location')).searchParams.get('code');
    const res = await fetch(`${app.baseUrl}/oauth2/token`, json({ grant_type: 'authorization_code', code, redirect_uri: redirectUri, client_id: client.clientId, client_secret: client.clientSecret }));
    const body = await res.json();
    assert.equal(res.status, 200, JSON.stringify(body));
    return body;
}

const bearer = (token) => ({ Authorization: `Bearer ${token}` });

test('an OAuth2 client\'s user access token is refused on every first-party route', async () => {
    const user = await registerVerifyLogin();
    const client = await createClient();
    const { access_token } = await oauthTokensFor(user, client, 'openid');

    const attempts = [
        ['GET', '/me'],
        ['PATCH', '/me', { firstName: 'Pwned' }],
        ['DELETE', '/me'],
        ['GET', '/me/sessions'],
        ['DELETE', '/me/sessions'],
        ['POST', '/logout/all'],
        ['POST', '/password/change', { currentPassword: password, newPassword: 'An0ther!Passw0rd' }],
        ['GET', '/me/mfa'],
        ['POST', '/me/mfa/setup'],
        ['POST', '/webauthn/registration/options', {}],
        ['POST', '/oauth2/authorize/confirm', { client_id: client.clientId, redirect_uri: redirectUri, scope: 'openid email profile' }],
        ['GET', `/oauth2/authorize?client_id=${client.clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code&scope=openid`],
        ['GET', '/oauth2/consent/sessions'],
    ];
    for (const [method, path, body] of attempts) {
        const res = await fetch(`${app.baseUrl}${path}`, {
            method,
            headers: { 'Content-Type': 'application/json', ...bearer(access_token) },
            ...(body ? { body: JSON.stringify(body) } : {}),
            redirect: 'manual',
        });
        assert.equal(res.status, 401, `${method} ${path} must refuse a third-party client's token (got ${res.status})`);
    }

    // Nothing above took effect: the account still exists, is unchanged, and its first-party session still works.
    const me = await fetch(`${app.baseUrl}/me`, { headers: bearer(user.accessToken) });
    assert.equal(me.status, 200);
    const meBody = await me.json();
    assert.equal(meBody.status, 'ACTIVE');
    assert.notEqual(meBody.profile?.firstName, 'Pwned');
});

test('a client_credentials machine token is refused on first-party routes and on /userinfo', async () => {
    const client = await createClient({ allowedScopes: ['openid', 'email'] });
    const cc = await (await fetch(`${app.baseUrl}/oauth2/token`, json({ grant_type: 'client_credentials', client_id: client.clientId, client_secret: client.clientSecret }))).json();
    assert.ok(cc.access_token);

    assert.equal((await fetch(`${app.baseUrl}/me`, { headers: bearer(cc.access_token) })).status, 401);
    assert.equal((await fetch(`${app.baseUrl}/userinfo`, { headers: bearer(cc.access_token) })).status, 401);
});

test('/userinfo accepts only OAuth2 user tokens carrying openid, and releases claims per scope', async () => {
    const user = await registerVerifyLogin();
    const client = await createClient();

    // A first-party token is not an OIDC access token.
    assert.equal((await fetch(`${app.baseUrl}/userinfo`, { headers: bearer(user.accessToken) })).status, 401);

    // openid only -> sub, but no email.
    const openidOnly = await oauthTokensFor(user, client, 'openid');
    const r1 = await fetch(`${app.baseUrl}/userinfo`, { headers: bearer(openidOnly.access_token) });
    assert.equal(r1.status, 200);
    assert.equal(r1.headers.get('cache-control'), 'no-store');
    const c1 = await r1.json();
    assert.equal(c1.sub, user.userId);
    assert.equal(c1.email, undefined, 'email must not be released without the email scope');

    // openid email -> email released.
    const withEmail = await oauthTokensFor(user, client, 'openid email');
    const c2 = await (await fetch(`${app.baseUrl}/userinfo`, { headers: bearer(withEmail.access_token) })).json();
    assert.equal(c2.email, user.email);
    assert.equal(c2.email_verified, true);

    // No openid scope -> insufficient_scope.
    const noOpenid = await oauthTokensFor(user, client, 'email');
    const r3 = await fetch(`${app.baseUrl}/userinfo`, { headers: bearer(noOpenid.access_token) });
    assert.equal(r3.status, 403);
    assert.equal((await r3.json()).error, 'insufficient_scope');
});

test('an OAuth2 refresh token is refused at /refresh — and stays revoked', async () => {
    const user = await registerVerifyLogin();
    const client = await createClient();
    const tokens = await oauthTokensFor(user, client, 'openid');

    const res = await fetch(`${app.baseUrl}/refresh`, json({ refreshToken: tokens.refresh_token }));
    assert.equal(res.status, 401);
    assert.equal((await res.json()).error, 'INVALID_REFRESH_TOKEN');

    // A client token presented at the first-party endpoint has leaked: it is not usable afterwards either.
    const again = await fetch(`${app.baseUrl}/oauth2/token`, json({ grant_type: 'refresh_token', refresh_token: tokens.refresh_token, client_id: client.clientId, client_secret: client.clientSecret }));
    assert.equal(again.status, 400);
});

test('a first-party refresh token is refused by the OAuth2 refresh grant — and stays revoked', async () => {
    const user = await registerVerifyLogin();
    const client = await createClient();

    const res = await fetch(`${app.baseUrl}/oauth2/token`, json({ grant_type: 'refresh_token', refresh_token: user.refreshToken, client_id: client.clientId, client_secret: client.clientSecret }));
    assert.equal(res.status, 400);
    assert.equal((await res.json()).error, 'INVALID_REFRESH_TOKEN');

    assert.equal((await fetch(`${app.baseUrl}/refresh`, json({ refreshToken: user.refreshToken }))).status, 401);
});

test('client B cannot redeem client A\'s refresh token', async () => {
    const user = await registerVerifyLogin();
    const clientA = await createClient();
    const clientB = await createClient({ clientType: 'public' });
    const tokens = await oauthTokensFor(user, clientA, 'openid email');

    const stolen = await fetch(`${app.baseUrl}/oauth2/token`, json({ grant_type: 'refresh_token', refresh_token: tokens.refresh_token, client_id: clientB.clientId }));
    assert.equal(stolen.status, 400);
    assert.equal((await stolen.json()).error, 'INVALID_REFRESH_TOKEN');

    // ...and the token is burnt for A as well.
    const legit = await fetch(`${app.baseUrl}/oauth2/token`, json({ grant_type: 'refresh_token', refresh_token: tokens.refresh_token, client_id: clientA.clientId, client_secret: clientA.clientSecret }));
    assert.equal(legit.status, 400);
});

test('the legitimate refresh paths still work: first-party at /refresh, OAuth2 at /oauth2/token by its own client', async () => {
    const user = await registerVerifyLogin();
    const r1 = await fetch(`${app.baseUrl}/refresh`, json({ refreshToken: user.refreshToken }));
    assert.equal(r1.status, 200);
    const refreshed = await r1.json();
    assert.equal((await fetch(`${app.baseUrl}/me`, { headers: bearer(refreshed.accessToken) })).status, 200);

    const client = await createClient();
    const tokens = await oauthTokensFor({ ...user, accessToken: refreshed.accessToken }, client, 'openid email');
    const r2 =await fetch(`${app.baseUrl}/oauth2/token`, json({ grant_type: 'refresh_token', refresh_token: tokens.refresh_token, client_id: client.clientId, client_secret: client.clientSecret }));
    assert.equal(r2.status, 200);
    const rotated = await r2.json();
    assert.equal(rotated.scope, 'openid email');
    assert.equal((await fetch(`${app.baseUrl}/userinfo`, { headers: bearer(rotated.access_token) })).status, 200);

    // The rotated token is still bound to the same client.
    const r3 = await fetch(`${app.baseUrl}/oauth2/token`, json({ grant_type: 'refresh_token', refresh_token: rotated.refresh_token, client_id: client.clientId, client_secret: client.clientSecret }));
    assert.equal(r3.status, 200);
});

test('verifyAccessToken: audience is enforced for first-party tokens and must equal client_id for OAuth2 tokens', async () => {
    const custom = await issueAccessToken({ sub: 'u1' }, { audience: 'https://api.other.example' });
    await assert.rejects(() => verifyAccessToken(custom.token), (err) => err.code === 'INVALID_TOKEN');
    const ok = await verifyAccessToken(custom.token, { audience: 'https://api.other.example' });
    assert.equal(ok.sub, 'u1');

    // A token claiming a client but with a mismatched aud (only forgeable with the signing key — the
    // check is defense in depth) is refused.
    const [kid, key] = getActiveSigningKey(app.state.signingKeys);
    const now = Math.floor(Date.now() / 1000);
    const odd = jwt.sign({ sub: 'u1', client_id: 'client-x', type: 'access_token', iss: app.state.config.issuer, aud: app.state.config.issuer, iat: now, exp: now + 60, jti: 'j1' }, key.privateKeyPem, { algorithm: 'RS256', keyid: kid });
    await assert.rejects(() => verifyAccessToken(odd, { accept: ['oauth2-user'] }), (err) => err.code === 'INVALID_TOKEN');
    await assert.rejects(() => verifyAccessToken(odd), (err) => err.code === 'INVALID_TOKEN', 'carrying client_id makes it an OAuth2 token, never first-party');
});

test('authContextMiddleware rejects a misconfigured accept list at construction', () => {
    assert.throws(() => authContextMiddleware({ accept: [] }));
    assert.throws(() => authContextMiddleware({ accept: ['everything'] }));
    assert.throws(() => authContextMiddleware({ accept: 'oauth2-user' }));
    assert.doesNotThrow(() => authContextMiddleware({ accept: ['first-party', 'oauth2-user', 'oauth2-client'] }));
});

test('sessionKindOf: explicit kind wins; pre-0.4.0 rows are inferred from their claims shape', () => {
    assert.equal(sessionKindOf({ kind: 'oauth2', claims: {} }), 'oauth2');
    assert.equal(sessionKindOf({ kind: 'first_party', claims: { clientId: 'c', scopes: [] } }), 'first_party');
    assert.equal(sessionKindOf({ kind: null, claims: { clientId: 'c', scopes: ['openid'] } }), 'oauth2');
    assert.equal(sessionKindOf({ claims: { role: 'member' } }), 'first_party');
    assert.equal(sessionKindOf({ claims: { clientId: 'c' } }), 'first_party');
    assert.equal(sessionKindOf(null), 'first_party');
});

test('tokenHandler passes a failed grant to next() instead of rejecting (would crash Express 4)', async () => {
    const req = { body: { grant_type: 'authorization_code', client_id: 'no-such-client', code: 'x', redirect_uri: redirectUri }, headers: {} };
    let forwarded;
    const result = tokenHandler(req, {}, (err) => { forwarded = err; });
    await assert.doesNotReject(result, 'the handler promise must not reject — Express 4 ignores it and the process dies');
    assert.equal(forwarded?.code, 'OAUTH_CLIENT_NOT_FOUND');
});
