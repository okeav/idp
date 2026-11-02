import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import { buildTestApp, withTemporaryApp, uniqueEmail } from './helpers/build-test-app.js';

// SSO issues found in the 0.3.0 audit, beyond account linking (see sso.test.js):
//  - `state` wasn't tied to the browser (login CSRF), and no PKCE / nonce;
//  - the redirect allowlist was off unless configured (open redirect);
//  - the provider's error was reflected before `state` was checked;
//  - Apple's id_token claims weren't checked, and its client secret lived 6 months;
//  - provider calls had no timeout; `extra` params were unbounded; /sso/:provider unthrottled.

const realFetch = globalThis.fetch;
const appOrigin = 'https://app.example.com';
const redirectUri = `${appOrigin}/cb`;
const providerCalls = [];
let googleProfile;
let appleIdToken; // (nonce) => id_token payload
let tokenEndpointHangs = false;

const { privateKey: applePrivateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
const unsignedJwt = (payload) => `${Buffer.from('{"alg":"RS256"}').toString('base64url')}.${Buffer.from(JSON.stringify(payload)).toString('base64url')}.sig`;

function stubProviders() {
    globalThis.fetch = async (input, init = {}) => {
        const url = String(input?.url ?? input);
        if (url === 'https://oauth2.googleapis.com/token' || url === 'https://appleid.apple.com/auth/token') {
            const body = Object.fromEntries(new URLSearchParams(init.body));
            providerCalls.push({ url, body });
            if (tokenEndpointHangs) {
                return new Promise((_, reject) => init.signal?.addEventListener('abort', () => reject(init.signal.reason)));
            }
            if (url.startsWith('https://appleid')) return Response.json({ id_token: unsignedJwt(appleIdToken(lastAuthorize.nonce)) });
            return Response.json({ access_token: 'provider-at' });
        }
        if (url === 'https://www.googleapis.com/oauth2/v3/userinfo') return Response.json(googleProfile);
        return realFetch(input, init);
    };
}

const config = (extra = {}) => ({
    oauthProviders: {
        google: { clientId: 'g-client', clientSecret: 'g-secret' },
        apple: { clientId: 'com.example.web', teamId: 'TEAM123456', keyId: 'KEY1234567', privateKeyPem: applePrivateKey.export({ type: 'pkcs8', format: 'pem' }) },
    },
    sso: { baseCallbackUrl: 'https://idp.test.local', allowedRedirectOrigins: [appOrigin] },
    ...extra,
});

let app;
let lastAuthorize = {};

before(async () => {
    stubProviders();
    app = await buildTestApp({ config: config() });
});

after(async () => {
    globalThis.fetch = realFetch;
    await app.stop();
});

/** GET /sso/:provider — resolves with the provider authorize params and the binding cookie. */
async function initiate(provider, { baseUrl = app.baseUrl, query = {} } = {}) {
    const qs = new URLSearchParams({ redirect_uri: redirectUri, ...query });
    const res = await realFetch(`${baseUrl}/sso/${provider}?${qs}`, { redirect: 'manual' });
    assert.equal(res.status, 302, await res.text());
    const authorize = new URL(res.headers.get('location')).searchParams;
    lastAuthorize = Object.fromEntries(authorize);
    return { authorize, cookie: res.headers.getSetCookie().map((c) => c.split(';')[0]).join('; '), setCookie: res.headers.getSetCookie() };
}

const callback = (provider, params, cookie, baseUrl = app.baseUrl) => realFetch(`${baseUrl}/sso/${provider}/callback?${new URLSearchParams(params)}`, { redirect: 'manual', headers: cookie ? { Cookie: cookie } : {} });

test('login CSRF: the callback completes only in the browser that started the login', async () => {
    googleProfile = { sub: 'g-csrf', email: uniqueEmail('csrf'), email_verified: true };
    const { authorize, cookie } = await initiate('google');
    const state = authorize.get('state');

    // The attacker's half-finished login, opened in the victim's browser (no binding cookie):
    const noCookie = await callback('google', { code: 'c', state });
    assert.equal(noCookie.status, 400);
    assert.equal((await noCookie.json()).error, 'INVALID_SSO_STATE');

    // …and the state was consumed by that attempt, so it can't be finished afterwards either.
    assert.equal((await callback('google', { code: 'c', state }, cookie)).status, 400);

    // Another browser's cookie doesn't fit a different login either.
    const a = await initiate('google');
    const b = await initiate('google');
    assert.equal((await callback('google', { code: 'c', state: a.authorize.get('state') }, b.cookie)).status, 400);

    // The genuine flow works.
    const ok = await initiate('google');
    const res = await callback('google', { code: 'c', state: ok.authorize.get('state') }, ok.cookie);
    assert.equal(res.status, 302);
    assert.equal(new URL(res.headers.get('location')).searchParams.get('ssoLogin'), 'success');
});

test('the binding cookie is httpOnly and short-lived', async () => {
    const { setCookie } = await initiate('google');
    const binding = setCookie.find((c) => c.startsWith('idp_sso_'));
    assert.match(binding, /HttpOnly/i);
    assert.match(binding, /SameSite=Lax/i);
    assert.match(binding, new RegExp(`Max-Age=${app.state.config.ttls.ssoState}`));
});

test('PKCE (S256) with Google: the verifier sent at the exchange matches the challenge sent at authorize', async () => {
    googleProfile = { sub: 'g-pkce', email: uniqueEmail('pkce'), email_verified: true };
    const { authorize, cookie } = await initiate('google');
    assert.equal(authorize.get('code_challenge_method'), 'S256');
    await callback('google', { code: 'c', state: authorize.get('state') }, cookie);
    const { body } = providerCalls.filter((c) => c.url.includes('googleapis')).at(-1);
    assert.equal(crypto.createHash('sha256').update(body.code_verifier).digest('base64url'), authorize.get('code_challenge'));
});

test('redirect allowlist fails closed: SSO providers without one refuse to start', async () => {
    await assert.rejects(buildTestApp({ config: { ...config(), sso: { baseCallbackUrl: 'https://idp.test.local' } } }), /allowedRedirectOrigins is required/);
    await assert.rejects(buildTestApp({ config: { ...config(), sso: { baseCallbackUrl: 'https://idp.test.local', allowedRedirectOrigins: ['https://app.example.com/path'] } } }), /is not an origin/);
});

test('only allowlisted https origins are redirect targets', async () => {
    for (const uri of ['https://evil.example.com/cb', 'javascript:alert(1)', 'http://app.example.com/cb', 'https://user:pw@app.example.com/cb']) {
        const res = await realFetch(`${app.baseUrl}/sso/google?redirect_uri=${encodeURIComponent(uri)}`, { redirect: 'manual' });
        assert.equal(res.status, 400, uri);
    }
});

test('a provider error is answered only after the state checks out, and never reflected verbatim', async () => {
    const forged = await callback('google', { error: 'access_denied', error_description: '<script>alert(1)</script>' });
    assert.equal(forged.status, 400);
    assert.equal((await forged.json()).error, 'INVALID_SSO_STATE');

    const { authorize, cookie } = await initiate('google');
    const res = await callback('google', { error: 'access_denied<b>', error_description: 'Phishing text here', state: authorize.get('state') }, cookie);
    assert.equal(res.status, 302);
    const location = new URL(res.headers.get('location'));
    assert.equal(location.origin + location.pathname, redirectUri);
    assert.equal(location.searchParams.get('error'), 'provider_error');
    assert.equal(location.searchParams.get('provider_error'), 'access_deniedb');
    assert.ok(!location.toString().includes('Phishing'));

    const noCode = await initiate('google');
    const missing = await callback('google', { state: noCode.authorize.get('state') }, noCode.cookie);
    assert.equal(new URL(missing.headers.get('location')).searchParams.get('error'), 'provider_error');
});

async function appleCallback(payloadFor) {
    appleIdToken = payloadFor;
    const { authorize, cookie } = await initiate('apple');
    assert.ok(authorize.get('nonce'), 'Apple authorize carries a nonce');
    return realFetch(`${app.baseUrl}/sso/apple/callback`, {
        method: 'POST', redirect: 'manual',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', Cookie: cookie },
        body: new URLSearchParams({ code: 'apple-code', state: authorize.get('state') }).toString(),
    });
}

test('Apple: the id_token must be for this client, from Apple, unexpired, and carry this login\'s nonce', async () => {
    const now = Math.floor(Date.now() / 1000);
    const good = (nonce) => ({ iss: 'https://appleid.apple.com', aud: 'com.example.web', exp: now + 600, nonce, sub: `apple-${Math.random()}`, email: uniqueEmail('apple'), email_verified: 'true' });

    for (const [why, mutate] of [
        ['wrong nonce', (p) => ({ ...p, nonce: 'replayed' })],
        ['wrong audience', (p) => ({ ...p, aud: 'com.attacker.app' })],
        ['wrong issuer', (p) => ({ ...p, iss: 'https://evil.example.com' })],
        ['expired', (p) => ({ ...p, exp: now - 3600 })],
    ]) {
        const res = await appleCallback((nonce) => mutate(good(nonce)));
        assert.equal(res.status, 400, why);
        assert.equal((await res.json()).error, 'SSO_PROVIDER_ERROR', why);
    }

    const ok = await appleCallback(good);
    assert.equal(ok.status, 302);
    assert.equal(new URL(ok.headers.get('location')).searchParams.get('ssoLogin'), 'success');
});

test('Apple: the binding cookie survives Apple\'s cross-site form POST (SameSite=None; Secure)', async () => {
    const { setCookie } = await initiate('apple');
    const binding = setCookie.find((c) => c.startsWith('idp_sso_'));
    assert.match(binding, /SameSite=None/i);
    assert.match(binding, /Secure/i);
});

test('Apple: the generated client secret lives 5 minutes, not 6 months', async () => {
    const now = Math.floor(Date.now() / 1000);
    await appleCallback((nonce) => ({ iss: 'https://appleid.apple.com', aud: 'com.example.web', exp: now + 600, nonce, sub: 'apple-ttl', email: uniqueEmail('apple-ttl'), email_verified: 'true' }));
    const { body } = providerCalls.filter((c) => c.url.includes('appleid')).at(-1);
    const secret = JSON.parse(Buffer.from(body.client_secret.split('.')[1], 'base64url').toString());
    assert.ok(secret.exp - secret.iat <= 300, `exp - iat = ${secret.exp - secret.iat}`);
});

test('a hung provider is abandoned after sso.providerTimeoutMs', async () => {
    await withTemporaryApp({ config: config({ sso: { baseCallbackUrl: 'https://idp.test.local', allowedRedirectOrigins: [appOrigin], providerTimeoutMs: 200 } }) }, async (temp) => {
        const { authorize, cookie } = await initiate('google', { baseUrl: temp.baseUrl });
        tokenEndpointHangs = true;
        try {
            const started = Date.now();
            const res = await callback('google', { code: 'c', state: authorize.get('state') }, cookie, temp.baseUrl);
            assert.equal(res.status, 500);
            assert.ok(Date.now() - started < 5000, 'gave up promptly');
        } finally {
            tokenEndpointHangs = false;
        }
    });
});

test('extra query params reach resolveAuthContext only as a few short strings', async () => {
    let seen;
    const hooks = { resolveAuthContext: async (_user, ctx) => { seen = ctx.extra; return { claims: {} }; } };
    await withTemporaryApp({ config: config(), hooks }, async (temp) => {
        googleProfile = { sub: 'g-extra', email: uniqueEmail('extra'), email_verified: true };
        const query = { roleHint: 'member', long: 'x'.repeat(300), ...Object.fromEntries(Array.from({ length: 15 }, (_, i) => [`k${i}`, 'v'])) };
        const { authorize, cookie } = await initiate('google', { baseUrl: temp.baseUrl, query });
        await callback('google', { code: 'c', state: authorize.get('state') }, cookie, temp.baseUrl);
        assert.equal(seen.roleHint, 'member');
        assert.equal(seen.long, undefined);
        assert.ok(Object.keys(seen).length <= 10);
    });
});

test('GET /sso/:provider is rate limited per IP', async () => {
    await withTemporaryApp({ config: { ...config(), rateLimiting: { enabled: true, ssoInitiate: { max: 2, windowSeconds: 60 } } } }, async (temp) => {
        const start = () => realFetch(`${temp.baseUrl}/sso/google?redirect_uri=${encodeURIComponent(redirectUri)}`, { redirect: 'manual' });
        assert.equal((await start()).status, 302);
        assert.equal((await start()).status, 302);
        assert.equal((await start()).status, 429);
    });
});
