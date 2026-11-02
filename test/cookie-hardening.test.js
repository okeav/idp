import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { buildTestApp, withTemporaryApp, uniqueEmail } from './helpers/build-test-app.js';
import { json } from './helpers/serve.js';
import { ssoBindingCookie } from '../src/sso/binding.js';

// Cookie tossing (a sibling subdomain planting session cookies the browser then sends first) and
// logout CSRF — from the second review.

const password = 'Str0ng!Passw0rd';
let app;

before(async () => {
    app = await buildTestApp(); // Secure cookies (NODE_ENV isn't 'development')
});

after(async () => {
    await app.stop();
});

const post = (path, body, headers, base = app.baseUrl) => fetch(`${base}${path}`, json(body, headers));

async function login(a = app) {
    const email = uniqueEmail('cookie');
    await post('/register', { email, password }, {}, a.baseUrl);
    const code = a.hookCalls.onVerificationEmailRequested.filter((c) => c.email === email).at(-1).verificationCode;
    await post('/register/verify-email', { email, code }, {}, a.baseUrl);
    const res = await post('/login', { email, password }, {}, a.baseUrl);
    const setCookie = res.headers.getSetCookie();
    const cookies = Object.fromEntries(setCookie.map((c) => c.split(';')[0].split('=')));
    return { email, setCookie, cookies, ...(await res.json()) };
}

test('session cookies are __Host- cookies: host-only, Secure, Path=/', async () => {
    const u = await login();
    const access = u.setCookie.find((c) => c.startsWith('__Host-access_token='));
    const refresh = u.setCookie.find((c) => c.startsWith('__Host-refresh_token='));
    for (const c of [access, refresh]) {
        assert.ok(c, u.setCookie.join(' | '));
        assert.match(c, /;\s*Secure/i);
        assert.match(c, /;\s*Path=\//i);
        assert.doesNotMatch(c, /;\s*Domain=/i);
    }
});

test('a planted unprefixed cookie is ignored; an explicit Bearer header wins over any cookie', async () => {
    const victim = await login();
    const attacker = await login();
    // A sibling subdomain can set `access_token` for the parent domain — but not `__Host-access_token`.
    const planted = await fetch(`${app.baseUrl}/me`, { headers: { Cookie: `access_token=${attacker.accessToken}; __Host-access_token=${victim.cookies['__Host-access_token']}` } });
    assert.equal((await planted.json()).email, victim.email);

    const both = await fetch(`${app.baseUrl}/me`, { headers: { Authorization: `Bearer ${victim.accessToken}`, Cookie: `__Host-access_token=${attacker.accessToken}` } });
    assert.equal((await both.json()).email, victim.email, 'the Authorization header is explicit; the cookie is whatever the browser holds');
});

test('/refresh: a token in the body wins over the cookie', async () => {
    const victim = await login();
    const attacker = await login();
    const res = await post('/refresh', { refreshToken: victim.refreshToken }, { Cookie: `__Host-refresh_token=${attacker.refreshToken}` });
    assert.equal(res.status, 200);
    // The attacker's token was not the one rotated.
    assert.equal((await post('/refresh', { refreshToken: attacker.refreshToken })).status, 200);
});

test('with cookies.domain: __Secure- names, and a request carrying a session cookie twice is refused', async () => {
    await withTemporaryApp({ config: { cookies: { domain: 'idp.test.local', secure: true } } }, async (temp) => {
        const u = await login(temp);
        assert.ok(u.setCookie.some((c) => c.startsWith('__Secure-refresh_token=') && /Domain=idp\.test\.local/i.test(c)), u.setCookie.join(' | '));

        const attacker = await login(temp);
        const tossed = await fetch(`${temp.baseUrl}/refresh`, {
            method: 'POST',
            headers: { Cookie: `__Secure-refresh_token=${attacker.refreshToken}; __Secure-refresh_token=${u.refreshToken}` },
        });
        assert.equal(tossed.status, 400);
        assert.equal((await tossed.json()).error, 'COOKIE_CONFLICT');
        const me = await fetch(`${temp.baseUrl}/me`, { headers: { Cookie: `__Secure-access_token=${attacker.accessToken}; __Secure-access_token=${u.accessToken}` } });
        assert.equal(me.status, 400);
        // Neither token was consumed.
        assert.equal((await post('/refresh', { refreshToken: u.refreshToken }, {}, temp.baseUrl)).status, 200);
    });
});

test('logout refuses a cross-origin browser request even with a token in the body (logout CSRF), and clears nothing', async () => {
    const u = await login();
    const forged = await fetch(`${app.baseUrl}/logout`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', Origin: 'https://evil.example.com', Cookie: `__Host-refresh_token=${u.refreshToken}` },
        body: new URLSearchParams({ refreshToken: 'junk' }).toString(),
    });
    assert.equal(forged.status, 403);
    assert.equal(forged.headers.getSetCookie().length, 0);
    assert.equal((await post('/refresh', { refreshToken: u.refreshToken })).status, 200, 'the session is intact');
});

test('the SSO binding cookie is always host-only and __Host- when Secure, even with cookies.domain', () => {
    const state = { config: { cookies: { domain: 'example.com', secure: true }, ttls: { ssoState: 600 } } };
    const lax = ssoBindingCookie(state, 'abcdef0123456789xyz', {});
    assert.ok(lax.name.startsWith('__Host-idp_sso_'));
    assert.equal(lax.options.domain, undefined);
    const formPost = ssoBindingCookie({ config: { cookies: { secure: false }, ttls: { ssoState: 600 } } }, 'abcdef0123456789xyz', { responseMode: 'form_post' });
    assert.ok(formPost.name.startsWith('__Host-'), 'SameSite=None forces Secure, so it is prefixed too');
});

test('cookie configuration is validated at startup', async () => {
    await assert.rejects(buildTestApp({ config: { cookies: { sameSite: 'laxx' } } }), /sameSite/);
    await assert.rejects(buildTestApp({ config: { cookies: { sameSite: 'none', secure: false } } }), /requires secure/);
    await assert.rejects(buildTestApp({ config: { cookies: { trustedOrigins: ['https://app.example.com/'] } } }), /exact origins/);
});
