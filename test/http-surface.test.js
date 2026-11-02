import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import cookieParserLib from 'cookie-parser';
import { buildTestApp, withTemporaryApp, uniqueEmail } from './helpers/build-test-app.js';
import { json } from './helpers/serve.js';
import { buildRouter, idpErrorHandler, IdpError } from '../src/index.js';

// HTTP-surface issues found in the 0.3.0 audit: the documented error handler
// echoed internal messages (DB errors, parser errors with the request body)
// and IdpError had no `status` (Express's default handler answered 500 for
// everything); token-bearing responses were cacheable; cookie-authenticated
// state changes had no defence beyond SameSite; /refresh had no body schema;
// self-registration could write `metadata`; bcrypt silently truncated long
// passwords; avatarUrl accepted javascript: URLs.

const password = 'Str0ng!Passw0rd';
const trustedOrigin = 'https://app.example.com';
let app;

before(async () => {
    app = await buildTestApp({ config: { cookies: { secure: false, sameSite: 'lax', trustedOrigins: [trustedOrigin] } } });
});

after(async () => {
    await app.stop();
});

const post = (path, body, headers, base = app.baseUrl) => fetch(`${base}${path}`, json(body, headers));

async function user(base = app.baseUrl, a = app) {
    const email = uniqueEmail('http');
    await post('/register', { email, password }, {}, base);
    const code = a.hookCalls.onVerificationEmailRequested.filter((c) => c.email === email).at(-1).verificationCode;
    await post('/register/verify-email', { email, code }, {}, base);
    const res = await post('/login', { email, password }, {}, base);
    const cookies = Object.fromEntries(res.headers.getSetCookie().map((c) => c.split(';')[0].split('=')));
    return { email, cookies, ...(await res.json()) };
}

/** A bare app: the package router plus idpErrorHandler, nothing else. */
async function withBareApp(fn, { errorHandler = true } = {}) {
    const bare = express();
    bare.use(cookieParserLib());
    bare.use(express.json({ limit: '1kb' }));
    bare.get('/boom', () => { throw new Error('E11000 duplicate key error collection: idp.IdpIdentityUser index: emailHash_1'); });
    bare.get('/idp-500', () => { throw new IdpError({ code: 'MFA_SECRET_UNREADABLE', httpStatus: 500, message: 'secret under key k-2023 failed to decrypt' }); });
    bare.use('/', buildRouter({}));
    if (errorHandler) bare.use(idpErrorHandler());
    const server = await new Promise((r) => { const s = bare.listen(0, () => r(s)); });
    try {
        await fn(`http://127.0.0.1:${server.address().port}`);
    } finally {
        await new Promise((r) => server.close(r));
    }
}

test('idpErrorHandler: client errors keep their message; internals never leak', async () => {
    await withBareApp(async (base) => {
        const unauth = await fetch(`${base}/me`);
        assert.equal(unauth.status, 401);
        assert.deepEqual(await unauth.json(), { error: 'AUTH_REQUIRED', message: 'Authentication is required to access this resource' });

        const boom = await fetch(`${base}/boom`);
        assert.equal(boom.status, 500);
        assert.deepEqual(await boom.json(), { error: 'INTERNAL_ERROR' }, 'no driver message (collection, index, values)');

        const idp500 = await fetch(`${base}/idp-500`);
        assert.equal(idp500.status, 500);
        assert.deepEqual(await idp500.json(), { error: 'MFA_SECRET_UNREADABLE' });

        const malformed = await fetch(`${base}/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{"email": "secret-value-xyz", oops' });
        assert.equal(malformed.status, 400);
        const malformedBody = await malformed.text();
        assert.ok(!malformedBody.includes('secret-value-xyz'), 'the parser error must not echo the body');

        const huge = await fetch(`${base}/login`, json({ email: 'a@b.co', password: 'x'.repeat(5000) }));
        assert.equal(huge.status, 413);
    });
});

test('IdpError carries status/statusCode, so even Express\'s default handler answers the right status', async () => {
    const e = new IdpError({ code: 'X', httpStatus: 429 });
    assert.equal(e.status, 429);
    assert.equal(e.statusCode, 429);
    assert.equal(e.expose, true);
    assert.equal(new IdpError({ code: 'Y' }).expose, false);
    await withBareApp(async (base) => {
        assert.equal((await fetch(`${base}/me`)).status, 401);
    }, { errorHandler: false });
});

test('responses are not cacheable — except the public discovery and JWKS documents', async () => {
    const login = await post('/login', { email: uniqueEmail('nobody'), password });
    assert.equal(login.headers.get('cache-control'), 'no-store');
    const u = await user();
    assert.equal((await fetch(`${app.baseUrl}/me`, { headers: { Authorization: `Bearer ${u.accessToken}` } })).headers.get('cache-control'), 'no-store');
    assert.match((await fetch(`${app.baseUrl}/.well-known/jwks.json`)).headers.get('cache-control'), /public/);
    assert.match((await fetch(`${app.baseUrl}/.well-known/openid-configuration`)).headers.get('cache-control'), /public/);
});

test('CSRF: a cookie-authenticated state change must come from a trusted origin', async () => {
    const u = await user();
    const cookie = { Cookie: `access_token=${u.cookies.access_token}` };
    const logoutAll = (headers) => fetch(`${app.baseUrl}/session/logout/all`, { method: 'POST', headers: { ...cookie, ...headers } });

    const evil = await logoutAll({ Origin: 'https://evil.example.com' });
    assert.equal(evil.status, 403);
    assert.equal((await evil.json()).error, 'CSRF_ORIGIN_REJECTED');
    assert.equal((await logoutAll({ 'Sec-Fetch-Site': 'cross-site' })).status, 403, 'a cross-site browser request without Origin');
    assert.equal((await logoutAll({ Origin: 'null' })).status, 403, 'an opaque origin (sandboxed iframe, data: URL)');

    // The session survived all of that.
    assert.equal((await fetch(`${app.baseUrl}/me`, { headers: { Authorization: `Bearer ${u.accessToken}` } })).status, 200);
    assert.equal((await logoutAll({ Origin: trustedOrigin })).status, 200, 'the configured frontend origin');
});

test('CSRF: same-origin requests, the issuer\'s own origin, non-browser clients and Bearer requests are unaffected', async () => {
    const a = await user();
    assert.equal((await fetch(`${app.baseUrl}/me`, { method: 'PATCH', headers: { 'Content-Type': 'application/json', Cookie: `access_token=${a.cookies.access_token}`, 'Sec-Fetch-Site': 'same-origin' }, body: '{"firstName":"Ok"}' })).status, 200);
    assert.equal((await fetch(`${app.baseUrl}/me`, { method: 'PATCH', headers: { 'Content-Type': 'application/json', Cookie: `access_token=${a.cookies.access_token}`, Origin: 'https://idp.test.local' }, body: '{"firstName":"Ok"}' })).status, 200);
    assert.equal((await fetch(`${app.baseUrl}/me`, { method: 'PATCH', headers: { 'Content-Type': 'application/json', Cookie: `access_token=${a.cookies.access_token}` }, body: '{"firstName":"Ok"}' })).status, 200, 'no Origin, no Sec-Fetch-Site: not a browser');
    assert.equal((await fetch(`${app.baseUrl}/me`, { method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${a.accessToken}`, Origin: 'https://evil.example.com' }, body: '{"firstName":"Ok"}' })).status, 200, 'a Bearer header is never attached by a browser on its own');
});

test('CSRF: /refresh is held to the same rule — with the cookie, and with a token in the body (it sets session cookies)', async () => {
    const u = await user();
    const viaCookie = await fetch(`${app.baseUrl}/session/refresh`, { method: 'POST', headers: { Cookie: `refresh_token=${u.cookies.refresh_token}; refresh_binding=${u.cookies.refresh_binding}`, Origin: 'https://evil.example.com' } });
    assert.equal(viaCookie.status, 403);
    // A forged form could post the ATTACKER's refresh token and sign the victim in as the attacker.
    const viaBody = await post('/session/refresh', { refreshToken: u.refreshToken }, { Origin: 'https://evil.example.com' });
    assert.equal(viaBody.status, 403);
    assert.equal((await post('/session/refresh', { refreshToken: u.refreshToken })).status, 200, 'non-browser clients are unaffected');
});

test('/refresh validates its body (a non-string token was a 500)', async () => {
    const res = await post('/session/refresh', { refreshToken: 123 });
    assert.equal(res.status, 400);
    assert.equal((await res.json()).error, 'VALIDATION_ERROR');
});

test('self-registration metadata is ignored unless registration.acceptMetadata is on', async () => {
    const email = uniqueEmail('meta');
    await post('/register', { email, password, metadata: { role: 'admin' } });
    assert.deepEqual((await app.state.storage.userRepository.findByEmail(email)).metadata, {});

    await withTemporaryApp({ config: { registration: { acceptMetadata: true } } }, async (temp) => {
        const e2 = uniqueEmail('meta-on');
        await fetch(`${temp.baseUrl}/register`, json({ email: e2, password, metadata: { referrer: 'newsletter' } }));
        assert.deepEqual((await temp.state.storage.userRepository.findByEmail(e2)).metadata, { referrer: 'newsletter' });
    });
});

test('passwords over 72 bytes are refused (bcrypt would silently ignore the rest)', async () => {
    const long = `Aa1!${'x'.repeat(69)}`; // 73 bytes
    assert.equal((await post('/register', { email: uniqueEmail('long'), password: long })).status, 400);
    const multibyte = `Aa1!${'é'.repeat(35)}`; // 4 + 70 bytes
    assert.equal((await post('/register', { email: uniqueEmail('mb'), password: multibyte })).status, 400);
    assert.equal((await post('/register', { email: uniqueEmail('ok'), password: `Aa1!${'x'.repeat(68)}` })).status, 201, 'exactly 72 bytes is fine');
});

test('profile fields: avatarUrl must be https; locale and zoneinfo must be well-formed', async () => {
    const u = await user();
    const patch = (body) => fetch(`${app.baseUrl}/me`, { method: 'PATCH', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${u.accessToken}` }, body: JSON.stringify(body) });
    for (const bad of [{ avatarUrl: 'javascript:alert(1)' }, { avatarUrl: 'data:image/png;base64,AAAA' }, { avatarUrl: 'http://x.example/a.png' }, { locale: '<script>' }, { zoneinfo: 'Europe/London; rm -rf' }]) {
        assert.equal((await patch(bad)).status, 400, JSON.stringify(bad));
    }
    assert.equal((await patch({ avatarUrl: 'https://cdn.example.com/a.png', locale: 'en-GB', zoneinfo: 'Europe/London' })).status, 200);
});

test('cookies.refreshTokenInBody: false keeps the refresh token out of JSON bodies (cookie only)', async () => {
    await withTemporaryApp({ config: { cookies: { secure: false, refreshTokenInBody: false } } }, async (temp) => {
        const u = await user(temp.baseUrl, temp);
        assert.equal(u.refreshToken, undefined);
        assert.ok(u.cookies.refresh_token, 'still set as the httpOnly cookie');
        const refreshed = await fetch(`${temp.baseUrl}/session/refresh`, { method: 'POST', headers: { Cookie: `refresh_token=${u.cookies.refresh_token}; refresh_binding=${u.cookies.refresh_binding}` } });
        assert.equal(refreshed.status, 200);
        assert.equal((await refreshed.json()).refreshToken, undefined);
    });
});
