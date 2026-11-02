import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import bcrypt from 'bcrypt';
import { buildTestApp, withTemporaryApp, uniqueEmail } from './helpers/build-test-app.js';
import { json } from './helpers/serve.js';
import { pkcePair, authorizeCode, exchangeCode } from './helpers/oauth.js';
import { issueMfaChallengeToken } from '../src/signing/token.service.js';
import { isAcceptableRedirectUri } from '../src/oauth2/redirect-uri.js';

// OAuth2 / OIDC issues found in the 0.3.0 audit: PKCE optional (and `plain`
// accepted, and downgradable), nonce taken from the token request, ID token
// claims ignoring scope, consent confirm accepting arbitrary client/scope/
// redirect (no binding to the request the user saw), client_secret_basic
// advertised but unimplemented, unauthenticated revoke/introspect, revoking
// consent or a client leaving its tokens alive, end-session revoking every
// session on any token it was shown, and dangerous redirect URIs registrable.

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
const payloadOf = (t) => JSON.parse(Buffer.from(t.split('.')[1], 'base64url').toString());

async function user(base = app.baseUrl, a = app) {
    const email = uniqueEmail('oa');
    await post('/register', { email, password }, {}, base);
    const code = a.hookCalls.onVerificationEmailRequested.filter((c) => c.email === email).at(-1).verificationCode;
    await post('/register/verify-email', { email, code }, {}, base);
    return { email, ...(await (await post('/login', { email, password }, {}, base)).json()) };
}

async function client(overrides = {}, base = app.baseUrl) {
    const res = await post('/oauth2/clients', {
        name: 'RP', slug: `rp-${Date.now()}-${Math.random().toString(36).slice(2)}`, redirectUris: [redirectUri],
        allowedScopes: ['openid', 'email', 'profile'], allowedGrants: ['authorization_code', 'refresh_token', 'client_credentials'], ...overrides,
    }, ADMIN, base);
    const c = await res.json();
    assert.equal(res.status, 201, JSON.stringify(c));
    await fetch(`${base}/oauth2/clients/${c.clientId}/approve`, { method: 'POST', headers: ADMIN });
    return c;
}

async function tokensFor(u, c, scope = 'openid email', extra = {}) {
    const { code, verifier } = await authorizeCode({ baseUrl: app.baseUrl, accessToken: u.accessToken, clientId: c.clientId, redirectUri, scope, ...extra });
    const { status, body } = await exchangeCode({ baseUrl: app.baseUrl, client: c, code, redirectUri, verifier });
    assert.equal(status, 200, JSON.stringify(body));
    return body;
}

const authorizeUrl = (c, params = {}) => `${app.baseUrl}/oauth2/authorize?${new URLSearchParams({ client_id: c.clientId, redirect_uri: redirectUri, response_type: 'code', scope: 'openid', ...params })}`;

test('PKCE is required (S256 only) — no challenge, plain, or a method-less challenge is refused', async () => {
    const u = await user();
    const c = await client();
    const { challenge } = pkcePair();
    for (const params of [{}, { code_challenge: challenge, code_challenge_method: 'plain' }, { code_challenge: challenge }]) {
        const res = await fetch(authorizeUrl(c, params), { headers: bearer(u.accessToken), redirect: 'manual' });
        assert.equal(res.status, 400, JSON.stringify(params));
    }
    const ok = await fetch(authorizeUrl(c, { code_challenge: challenge, code_challenge_method: 'S256' }), { headers: bearer(u.accessToken), redirect: 'manual' });
    assert.equal(ok.status, 200);
});

test('PKCE: a wrong or malformed verifier is refused, and the code is spent', async () => {
    const u = await user();
    const c = await client();
    const { code } = await authorizeCode({ baseUrl: app.baseUrl, accessToken: u.accessToken, clientId: c.clientId, redirectUri });
    const wrong = await exchangeCode({ baseUrl: app.baseUrl, client: c, code, redirectUri, verifier: pkcePair().verifier });
    assert.equal(wrong.status, 400);
    assert.equal(wrong.body.error, 'INVALID_GRANT');

    const { code: code2 } = await authorizeCode({ baseUrl: app.baseUrl, accessToken: u.accessToken, clientId: c.clientId, redirectUri });
    const malformed = await exchangeCode({ baseUrl: app.baseUrl, client: c, code: code2, redirectUri, verifier: 'short' });
    assert.equal(malformed.status, 400);
    const missing = await exchangeCode({ baseUrl: app.baseUrl, client: c, code: code2, redirectUri });
    assert.equal(missing.body.error, 'INVALID_GRANT');
});

test('requirePkce "public": a confidential client may skip PKCE — but a verifier on a challenge-less code is a downgrade and refused', async () => {
    await withTemporaryApp({ config: { oauth2: { requirePkce: 'public' } } }, async (temp) => {
        const u = await user(temp.baseUrl, temp);
        const c = await client({}, temp.baseUrl);
        const pub = await client({ clientType: 'public' }, temp.baseUrl);

        const noPkce = async (cl) => {
            const res = await fetch(`${temp.baseUrl}/oauth2/authorize?${new URLSearchParams({ client_id: cl.clientId, redirect_uri: redirectUri, response_type: 'code' })}`, { headers: bearer(u.accessToken), redirect: 'manual' });
            return res;
        };
        assert.equal((await noPkce(pub)).status, 400, 'public clients always need PKCE');

        const consent = await (await noPkce(c)).json();
        const confirm = await fetch(`${temp.baseUrl}/oauth2/authorize/confirm`, { ...json({ consent_challenge: consent.consent_challenge }, bearer(u.accessToken)), redirect: 'manual' });
        const code = new URL(confirm.headers.get('location')).searchParams.get('code');
        const downgrade = await exchangeCode({ baseUrl: temp.baseUrl, client: c, code, redirectUri, verifier: pkcePair().verifier });
        assert.equal(downgrade.body.error, 'INVALID_GRANT');

        // Consent now exists, so /authorize redirects straight back with a code; without a verifier it redeems.
        const again = await noPkce(c);
        assert.equal(again.status, 302);
        const code2 = new URL(again.headers.get('location')).searchParams.get('code');
        assert.equal((await exchangeCode({ baseUrl: temp.baseUrl, client: c, code: code2, redirectUri })).status, 200);
    });
});

test('the ID token carries the nonce from the authorization request — not one supplied at the token endpoint', async () => {
    const u = await user();
    const c = await client();
    const { code, verifier } = await authorizeCode({ baseUrl: app.baseUrl, accessToken: u.accessToken, clientId: c.clientId, redirectUri, nonce: 'n-0S6_WzA2Mj' });
    const res = await post('/oauth2/token', { grant_type: 'authorization_code', code, redirect_uri: redirectUri, client_id: c.clientId, client_secret: c.clientSecret, code_verifier: verifier, nonce: 'attacker-chosen' });
    const body = await res.json();
    assert.equal(res.status, 200, JSON.stringify(body));
    assert.equal(payloadOf(body.id_token).nonce, 'n-0S6_WzA2Mj');
});

test('ID token claims follow the granted scopes; azp and auth_time are present', async () => {
    const u = await user();
    const c = await client();
    const openidOnly = payloadOf((await tokensFor(u, c, 'openid')).id_token);
    assert.equal(openidOnly.email, undefined);
    assert.equal(openidOnly.name, undefined);
    assert.equal(openidOnly.azp, c.clientId);
    assert.equal(openidOnly.auth_time, payloadOf(u.accessToken).auth_time);

    const withEmail = payloadOf((await tokensFor(u, c, 'openid email')).id_token);
    assert.equal(withEmail.email, u.email);
    assert.equal(withEmail.email_verified, true);
});

test('consent: confirm needs the challenge the user\'s own /authorize issued — once, by that user', async () => {
    const victim = await user();
    const other = await user();
    const c = await client();
    const pkce = pkcePair();
    const authz = await (await fetch(authorizeUrl(c, { code_challenge: pkce.challenge, code_challenge_method: 'S256' }), { headers: bearer(victim.accessToken) })).json();

    // The classic forged confirm (client/scope/redirect in the body) is not accepted at all.
    const forged = await post('/oauth2/authorize/confirm', { client_id: c.clientId, redirect_uri: redirectUri, scope: 'openid email profile' }, bearer(victim.accessToken));
    assert.equal(forged.status, 400);

    // Another user can't redeem the victim's challenge…
    const stolen = await fetch(`${app.baseUrl}/oauth2/authorize/confirm`, { ...json({ consent_challenge: authz.consent_challenge }, bearer(other.accessToken)), redirect: 'manual' });
    assert.equal(stolen.status, 400);
    assert.equal((await stolen.json()).error, 'INVALID_CONSENT_CHALLENGE');

    // …and that attempt burnt it, so it can't be redeemed afterwards either.
    const after = await fetch(`${app.baseUrl}/oauth2/authorize/confirm`, { ...json({ consent_challenge: authz.consent_challenge }, bearer(victim.accessToken)), redirect: 'manual' });
    assert.equal(after.status, 400);

    // A fresh challenge works once.
    const authz2 = await (await fetch(authorizeUrl(c, { code_challenge: pkce.challenge, code_challenge_method: 'S256' }), { headers: bearer(victim.accessToken) })).json();
    const confirm = () => fetch(`${app.baseUrl}/oauth2/authorize/confirm`, { ...json({ consent_challenge: authz2.consent_challenge }, bearer(victim.accessToken)), redirect: 'manual' });
    assert.equal((await confirm()).status, 302);
    assert.equal((await confirm()).status, 400, 'single use');
});

test('client_secret_basic works (form-encoded credentials); mixing methods is refused', async () => {
    const c = await client();
    const basic = (id, secret) => `Basic ${Buffer.from(`${encodeURIComponent(id)}:${encodeURIComponent(secret)}`).toString('base64')}`;
    const ok = await post('/oauth2/token', { grant_type: 'client_credentials' }, { Authorization: basic(c.clientId, c.clientSecret) });
    assert.equal(ok.status, 200, await ok.clone().text());
    assert.equal(ok.headers.get('cache-control'), 'no-store');
    assert.equal(ok.headers.get('pragma'), 'no-cache');

    const both = await post('/oauth2/token', { grant_type: 'client_credentials', client_secret: c.clientSecret }, { Authorization: basic(c.clientId, c.clientSecret) });
    assert.equal(both.status, 400);
    const mismatch = await post('/oauth2/token', { grant_type: 'client_credentials', client_id: 'someone-else' }, { Authorization: basic(c.clientId, c.clientSecret) });
    assert.equal(mismatch.status, 401);
});

test('client authentication failures are indistinguishable: unknown client, wrong secret, inactive client', async () => {
    const c = await client();
    const inactive = await client();
    await fetch(`${app.baseUrl}/oauth2/clients/${inactive.clientId}`, { method: 'DELETE', headers: ADMIN });
    const attempts = [
        { client_id: 'no-such-client', client_secret: 'x' },
        { client_id: c.clientId, client_secret: 'wrong' },
        { client_id: inactive.clientId, client_secret: inactive.clientSecret },
    ];
    const bodies = [];
    for (const creds of attempts) {
        const res = await post('/oauth2/token', { grant_type: 'client_credentials', ...creds });
        assert.equal(res.status, 401);
        bodies.push(await res.json());
    }
    assert.deepEqual(bodies[0], bodies[1]);
    assert.deepEqual(bodies[1], bodies[2]);
    assert.equal(bodies[0].error, 'INVALID_CLIENT');
});

test('a pre-0.4.0 bcrypt client-secret hash still verifies, and is upgraded to HMAC on use', async () => {
    const c = await client();
    await app.state.storage.oauthClientRepository.updateByClientId(c.clientId, { clientSecretHash: await bcrypt.hash(c.clientSecret, 4) });
    const res = await post('/oauth2/token', { grant_type: 'client_credentials', client_id: c.clientId, client_secret: c.clientSecret });
    assert.equal(res.status, 200);
    const stored = await app.state.storage.oauthClientRepository.findByClientId(c.clientId, { includeSecret: true });
    assert.match(stored.clientSecretHash, /^hmac-sha256:[0-9a-f]{64}$/);
    assert.equal((await post('/oauth2/token', { grant_type: 'client_credentials', client_id: c.clientId, client_secret: c.clientSecret })).status, 200);
});

test('revoke: needs client authentication and only touches the caller\'s own tokens', async () => {
    const u = await user();
    const a = await client();
    const b = await client();
    const tokens = await tokensFor(u, a);

    assert.equal((await post('/oauth2/token/revoke', { token: tokens.refresh_token })).status, 401, 'no client authentication');

    // Client B "revokes" A's tokens: answered 200 (RFC 7009), but nothing happens.
    assert.equal((await post('/oauth2/token/revoke', { token: tokens.refresh_token, client_id: b.clientId, client_secret: b.clientSecret })).status, 200);
    assert.equal((await fetch(`${app.baseUrl}/userinfo`, { headers: bearer(tokens.access_token) })).status, 200);

    // A revokes its access token (a JWT): the paired session ends.
    assert.equal((await post('/oauth2/token/revoke', { token: tokens.access_token, client_id: a.clientId, client_secret: a.clientSecret })).status, 200);
    assert.equal((await fetch(`${app.baseUrl}/userinfo`, { headers: bearer(tokens.access_token) })).status, 401);
    const refresh = await post('/oauth2/token', { grant_type: 'refresh_token', refresh_token: tokens.refresh_token, client_id: a.clientId, client_secret: a.clientSecret });
    assert.equal(refresh.status, 400);
});

test('introspect: only an authenticated confidential client, and only for its own tokens', async () => {
    const u = await user();
    const a = await client();
    const b = await client();
    const pub = await client({ clientType: 'public' });
    const tokens = await tokensFor(u, a, 'openid email');

    assert.equal((await post('/oauth2/token/introspect', { token: tokens.access_token })).status, 401);
    assert.equal((await post('/oauth2/token/introspect', { token: tokens.access_token, client_id: pub.clientId })).status, 401);
    assert.equal((await post('/oauth2/token/introspect', { token: tokens.access_token }, bearer(u.accessToken))).status, 401, 'a user session is not a client credential');

    const own = await (await post('/oauth2/token/introspect', { token: tokens.access_token, client_id: a.clientId, client_secret: a.clientSecret })).json();
    assert.equal(own.active, true);
    assert.equal(own.client_id, a.clientId);
    assert.equal(own.sub, u.userId);
    assert.equal(own.scope, 'openid email');
    const ownRefresh = await (await post('/oauth2/token/introspect', { token: tokens.refresh_token, client_id: a.clientId, client_secret: a.clientSecret })).json();
    assert.equal(ownRefresh.active, true);
    assert.equal(ownRefresh.token_type, 'refresh_token');

    for (const token of [tokens.access_token, tokens.refresh_token, u.accessToken, u.refreshToken]) {
        const other = await (await post('/oauth2/token/introspect', { token, client_id: b.clientId, client_secret: b.clientSecret })).json();
        assert.deepEqual(other, { active: false });
    }
});

test('revoking consent ends the client\'s tokens for that user', async () => {
    const u = await user();
    const c = await client();
    const tokens = await tokensFor(u, c);
    assert.equal((await fetch(`${app.baseUrl}/userinfo`, { headers: bearer(tokens.access_token) })).status, 200);

    const res = await fetch(`${app.baseUrl}/oauth2/consent/sessions/${c.clientId}`, { method: 'DELETE', headers: bearer(u.accessToken) });
    assert.equal(res.status, 200);
    assert.equal((await fetch(`${app.baseUrl}/userinfo`, { headers: bearer(tokens.access_token) })).status, 401);
    assert.equal((await post('/oauth2/token', { grant_type: 'refresh_token', refresh_token: tokens.refresh_token, client_id: c.clientId, client_secret: c.clientSecret })).status, 400);
    // The user's own first-party session is untouched.
    assert.equal((await fetch(`${app.baseUrl}/me`, { headers: bearer(u.accessToken) })).status, 200);
});

test('deactivating a client ends every user\'s tokens for it', async () => {
    const u1 = await user();
    const u2 = await user();
    const c = await client();
    const t1 = await tokensFor(u1, c);
    const t2 = await tokensFor(u2, c);
    await fetch(`${app.baseUrl}/oauth2/clients/${c.clientId}`, { method: 'DELETE', headers: ADMIN });
    for (const t of [t1, t2]) assert.equal((await fetch(`${app.baseUrl}/userinfo`, { headers: bearer(t.access_token) })).status, 401);
});

test('end-session: only a real ID token is a hint, and it ends only that client\'s sessions', async () => {
    const u = await user();
    const a = await client();
    const b = await client();
    const ta = await tokensFor(u, a);
    const tb = await tokensFor(u, b);

    // An MFA challenge token (obtainable with just the password) or an access token is not a hint.
    const challenge = await issueMfaChallengeToken(app.state, u.userId);
    for (const hint of [challenge, ta.access_token, u.accessToken]) {
        const res = await fetch(`${app.baseUrl}/oidc/end-session?id_token_hint=${hint}`);
        assert.equal(res.status, 400);
    }

    // A hint alone (ID tokens end up in URLs and logs) signs nobody out of anything.
    const hintOnly = await fetch(`${app.baseUrl}/oidc/end-session?id_token_hint=${ta.id_token}`);
    assert.equal(hintOnly.status, 200);
    assert.equal((await fetch(`${app.baseUrl}/userinfo`, { headers: bearer(ta.access_token) })).status, 200, 'a bare hint ends nothing');

    // From the user's own browser (their IdP session cookie comes along), it ends the hinted client's sessions.
    const own = await (await post('/login', { email: u.email, password })).json();
    const res = await fetch(`${app.baseUrl}/oidc/end-session?id_token_hint=${ta.id_token}`, { headers: { Cookie: `__Host-access_token=${own.accessToken}` } });
    assert.equal(res.status, 200);
    assert.equal((await fetch(`${app.baseUrl}/userinfo`, { headers: bearer(ta.access_token) })).status, 401, 'the hinted client\'s session ended');
    assert.equal((await fetch(`${app.baseUrl}/userinfo`, { headers: bearer(tb.access_token) })).status, 200, 'another client\'s session did not');
    assert.equal((await fetch(`${app.baseUrl}/me`, { headers: bearer(u.accessToken) })).status, 200, 'nor did the user\'s other IdP session');

    // A hint for one user while signed in as another is refused.
    const other = await user();
    const mismatch = await fetch(`${app.baseUrl}/oidc/end-session?id_token_hint=${tb.id_token}`, { headers: { Cookie: `__Host-access_token=${other.accessToken}` } });
    assert.equal(mismatch.status, 400);
});

test('end-session with the browser\'s IdP session ends that session and clears its cookies', async () => {
    const u = await user();
    const res = await fetch(`${app.baseUrl}/oidc/end-session`, { headers: { Cookie: `__Host-access_token=${u.accessToken}` } });
    assert.equal(res.status, 200);
    assert.ok(res.headers.getSetCookie().some((c) => c.startsWith('__Host-access_token=;')));
    assert.equal((await fetch(`${app.baseUrl}/me`, { headers: bearer(u.accessToken) })).status, 401);
});

test('redirect URIs: only https, loopback http, or reverse-DNS native schemes — never a fragment', async () => {
    for (const bad of ['javascript:alert(1)//', 'data:text/html,hi', 'http://client.example.com/cb', 'https://client.example.com/cb#frag', 'file:///etc/passwd', 'https://user:pw@client.example.com/cb', 'myapp:/cb']) {
        assert.equal(isAcceptableRedirectUri(bad), false, bad);
        const res = await post('/oauth2/clients', { name: 'X', slug: `x-${Math.random()}`, redirectUris: [bad] }, ADMIN);
        assert.equal(res.status, 400, bad);
    }
    for (const good of ['https://client.example.com/cb', 'http://localhost:3000/cb', 'http://127.0.0.1/cb', 'http://[::1]:8080/cb', 'com.example.app:/oauth2redirect']) {
        assert.equal(isAcceptableRedirectUri(good), true, good);
    }
});

test('GET /oauth2/consent validates its query (no operator objects reach the database)', async () => {
    const u = await user();
    const res = await fetch(`${app.baseUrl}/oauth2/consent?client_id[$ne]=x`, { headers: bearer(u.accessToken) });
    assert.equal(res.status, 400);
});

test('the token endpoint is rate limited per IP', async () => {
    await withTemporaryApp({ config: { rateLimiting: { enabled: true, oauth2Token: { max: 2, windowSeconds: 60 } } } }, async (temp) => {
        const t = () => fetch(`${temp.baseUrl}/oauth2/token`, json({ grant_type: 'client_credentials', client_id: 'x', client_secret: 'y' }));
        assert.equal((await t()).status, 401);
        assert.equal((await t()).status, 401);
        assert.equal((await t()).status, 429);
    });
});

test('discovery advertises only what is implemented', async () => {
    const d = await (await fetch(`${app.baseUrl}/.well-known/openid-configuration`)).json();
    assert.deepEqual(d.code_challenge_methods_supported, ['S256']);
    assert.ok(d.token_endpoint_auth_methods_supported.includes('client_secret_basic'));
    assert.equal(d.authorization_response_iss_parameter_supported, true);
});
