import { test, before, after, mock } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import { generate as generateTotp } from 'otplib';
import { pkcePair } from './helpers/oauth.js';
import { stubStorage } from './helpers/stub-storage.js';
import { MemoryAttemptCounterRepository } from '../src/mfa/memory-attempt-counter.js';
import express from 'express';
import cookieParserLib from 'cookie-parser';
import { buildRouter } from '../src/routes/build-router.js';
import { setState } from '../src/config/state.js';
import { refreshCookieBinding, readRefreshCookie } from '../src/utils/cookies.js';
import { buildTestApp, withTemporaryApp, uniqueEmail, waitForHookCall, TEST_SECURITY } from './helpers/build-test-app.js';
import { hashOpaqueToken, HASH_PURPOSES } from '../src/signing/token.service.js';
import { json } from './helpers/serve.js';
import { configFromEnv, checkClockSkew } from '../src/index.js';
import { createMongoStorage } from '../src/storage/mongo/index.js';
import { startClockSkewGuard } from '../src/security/clock-skew.js';

// Closing the limitations left after 0.4.0's second round (part 2): per-request login challenges, the
// path-scoped refresh cookie, and the fixes from their review. Part 1: enterprise-hardening.test.js.

const password = 'Str0ng!Passw0rd';
const ISSUER_ORIGIN = 'https://idp.test.local';
let app;

before(async () => {
    app = await buildTestApp();
});

after(async () => {
    await app.stop();
});

const post = (base, path, body, headers) => fetch(`${base}${path}`, json(body, headers));

async function registered(target = app) {
    const email = uniqueEmail('ent');
    await post(target.baseUrl, '/register', { email, password });
    const code = target.hookCalls.onVerificationEmailRequested.filter((c) => c.email === email).at(-1).verificationCode;
    await post(target.baseUrl, '/register/verify-email', { email, code });
    return email;
}

async function loggedIn(target = app) {
    const email = await registered(target);
    return { email, ...(await (await post(target.baseUrl, '/login', { email, password })).json()) };
}


const LOCKOUT = { verificationCodeLockout: { maxFailedAttempts: 3, windowSeconds: 3600, lockSeconds: 3600 } };
const lastCode = (target, email) => target.hookCalls.onVerificationEmailRequested.filter((c) => c.email === email).at(-1);
const ticketCookieOf = (res) => res.headers.getSetCookie().find((c) => c.startsWith('__Host-verification_ticket=')).split(';')[0];

async function strangerLocks(target, email, code) {
    const wrong = code === '123456' ? '654321' : '123456';
    for (let i = 0; i < 3; i += 1) await post(target.baseUrl, '/register/verify-email', { email, code: wrong });
    assert.equal((await post(target.baseUrl, '/register/verify-email', { email, code })).status, 429, 'the address budget is spent');
}

// ── login challenges (prompt=login / max_age) ────────────────────────────────

const redirectUri = 'https://rp.example.com/cb';
const ADMIN = { 'x-test-admin': 'yes' };

async function rpClient() {
    const c = await (await post(app.baseUrl, '/oauth2/clients', {
        name: 'RP', slug: `ent-${crypto.randomUUID()}`, redirectUris: [redirectUri],
        allowedScopes: ['openid'], allowedGrants: ['authorization_code', 'refresh_token'],
    }, ADMIN)).json();
    await fetch(`${app.baseUrl}/oauth2/clients/${c.clientId}/approve`, { method: 'POST', headers: ADMIN });
    return c;
}

function authorize(clientId, accessToken, extra = {}) {
    const { challenge } = pkcePair();
    const qs = new URLSearchParams({ client_id: clientId, redirect_uri: redirectUri, response_type: 'code', scope: 'openid', code_challenge: challenge, code_challenge_method: 'S256', ...extra });
    return fetch(`${app.baseUrl}/oauth2/authorize?${qs}`, { headers: accessToken ? { Authorization: `Bearer ${accessToken}` } : {}, redirect: 'manual' });
}

const challengeFor = async (clientId, accessToken, extra = { prompt: 'login' }) => (await (await authorize(clientId, accessToken, extra)).json()).login_challenge;

test('prompt=login: a login made with the login_challenge satisfies the repeated request — once', async () => {
    const c = await rpClient();
    const u = await loggedIn();
    const loginChallenge = await challengeFor(c.clientId, u.accessToken);
    assert.ok(loginChallenge);

    // A new login WITHOUT the challenge doesn't count, however recent.
    const unbound = await (await post(app.baseUrl, '/login', { email: u.email, password })).json();
    assert.equal((await authorize(c.clientId, unbound.accessToken, { prompt: 'login', login_challenge: loginChallenge })).status, 401);

    const bound = await (await post(app.baseUrl, '/login', { email: u.email, password, login_challenge: loginChallenge })).json();
    const res = await authorize(c.clientId, bound.accessToken, { prompt: 'login', login_challenge: loginChallenge });
    assert.equal(res.status, 200);
    assert.equal((await res.json()).action, 'consent_required');
    assert.equal((await authorize(c.clientId, bound.accessToken, { prompt: 'login', login_challenge: loginChallenge })).status, 401, 'single use');
});

test('a login_challenge is bound to its client and to the session that signed in for it', async () => {
    const c = await rpClient();
    const other = await rpClient();
    const victim = await loggedIn();
    const loginChallenge = await challengeFor(c.clientId, victim.accessToken);
    const bound = await (await post(app.baseUrl, '/login', { email: victim.email, password, login_challenge: loginChallenge })).json();
    assert.equal((await authorize(other.clientId, bound.accessToken, { prompt: 'login', login_challenge: loginChallenge })).status, 401, 'another client');

    const attacker = await loggedIn();
    assert.equal((await authorize(c.clientId, attacker.accessToken, { prompt: 'login', login_challenge: loginChallenge })).status, 401, 'another session');
    // A second sign-in can't re-bind it.
    const second = await (await post(app.baseUrl, '/login', { email: attacker.email, password, login_challenge: loginChallenge })).json();
    assert.equal((await authorize(c.clientId, second.accessToken, { prompt: 'login', login_challenge: loginChallenge })).status, 401);
    assert.equal((await authorize(c.clientId, bound.accessToken, { prompt: 'login', login_challenge: loginChallenge })).status, 200);
});

test('the challenge carries through the MFA step, and satisfies max_age too', async () => {
    const c = await rpClient();
    const u = await loggedIn();
    const auth = { Authorization: `Bearer ${u.accessToken}` };
    const { secret } = await (await fetch(`${app.baseUrl}/me/mfa/setup`, { method: 'POST', headers: auth })).json();
    const { recoveryCodes } = await (await post(app.baseUrl, '/me/mfa/confirm', { code: await generateTotp({ secret }) }, auth)).json();

    const loginChallenge = await challengeFor(c.clientId, null, { max_age: '0' });
    assert.ok(loginChallenge, 'issued to an unauthenticated request too');
    const { mfaChallengeToken } = await (await post(app.baseUrl, '/login', { email: u.email, password, login_challenge: loginChallenge })).json();
    const done = await (await post(app.baseUrl, '/mfa/verify', { mfaChallengeToken, code: recoveryCodes[0] })).json();
    assert.equal((await authorize(c.clientId, done.accessToken, { max_age: '0', login_challenge: loginChallenge })).status, 200);
});

test('malformed login_challenge values are refused by the schemas', async () => {
    const c = await rpClient();
    const u = await loggedIn();
    assert.equal((await authorize(c.clientId, u.accessToken, { prompt: 'login', login_challenge: 'x' })).status, 400);
    assert.equal((await post(app.baseUrl, '/login', { email: u.email, password, login_challenge: '../../etc' })).status, 400);
});

test('a magic-link sign-in made with the login_challenge satisfies prompt=login', async () => {
    const c = await rpClient();
    const loginChallenge = await challengeFor(c.clientId, null);
    assert.match(loginChallenge, /^[A-Za-z0-9_-]{43}$/);
    const email = uniqueEmail('ml-lc');
    await post(app.baseUrl, '/magic-link/request', { email });
    const { magicLinkToken } = app.hookCalls.onMagicLinkRequested.filter((x) => x.email === email).at(-1);
    const { accessToken } = await (await post(app.baseUrl, '/magic-link/verify', { token: magicLinkToken, login_challenge: loginChallenge })).json();
    assert.equal((await authorize(c.clientId, accessToken, { prompt: 'login', login_challenge: loginChallenge })).status, 200);
});

// ── the refresh cookie: scoped to /session, bound to a host-only cookie ──────

const refreshPair = (res) => Object.fromEntries(res.headers.getSetCookie().filter((c) => /^__Secure-refresh_token=|^__Host-refresh_binding=/.test(c)).map((c) => c.split(';')[0].split('=')));
const asCookie = (pair) => Object.entries(pair).map(([k, v]) => `${k}=${v}`).join('; ');

async function browserLogin() {
    const email = await registered();
    const res = await post(app.baseUrl, '/login', { email, password }, { Origin: ISSUER_ORIGIN });
    return refreshPair(res);
}

test('a planted refresh cookie is never used, nor does it block the real one; the real pair refreshes and is rotated', async () => {
    const victim = await browserLogin();
    const attacker = await browserLogin();
    const refresh = (cookie) => post(app.baseUrl, '/session/refresh', {}, { Cookie: cookie, Origin: ISSUER_ORIGIN });
    const planted = `__Secure-refresh_token=${attacker['__Secure-refresh_token']}`;

    // What a sibling subdomain can plant: __Secure- (not __Host-) refresh cookies — but not the __Host- binding.
    for (const cookie of [planted, `${planted}; __Host-refresh_binding=${victim['__Host-refresh_binding']}`]) {
        const res = await refresh(cookie);
        assert.equal(res.status, 400, cookie);
        assert.equal((await res.json()).error, 'REFRESH_TOKEN_REQUIRED', 'no usable refresh cookie');
    }
    // Planted in front of the real pair (the browser sends both): the real one is used, the planted one untouched.
    const both = await refresh(`${planted}; ${asCookie(victim)}`);
    assert.equal(both.status, 200);
    assert.equal((await post(app.baseUrl, '/session/refresh', { refreshToken: attacker['__Secure-refresh_token'] })).status, 200);

    const rotated = refreshPair(both);
    assert.notEqual(rotated['__Secure-refresh_token'], victim['__Secure-refresh_token']);
    assert.notEqual(rotated['__Host-refresh_binding'], victim['__Host-refresh_binding']);
    assert.equal((await refresh(asCookie(rotated))).status, 200);
});

test('a planted refresh cookie does not stop logout: the real session ends and the cookies are cleared', async () => {
    const victim = await browserLogin();
    const attacker = await browserLogin();
    const res = await post(app.baseUrl, '/session/logout', {}, { Cookie: `__Secure-refresh_token=${attacker['__Secure-refresh_token']}; ${asCookie(victim)}`, Origin: ISSUER_ORIGIN });
    assert.equal(res.status, 200);
    assert.ok(res.headers.getSetCookie().some((c) => c.startsWith('__Secure-refresh_token=;')));
    assert.equal((await post(app.baseUrl, '/session/refresh', { refreshToken: victim['__Secure-refresh_token'] })).status, 401);
});

test('a malformed binding cookie is a plain miss, not a 500', async () => {
    const victim = await browserLogin();
    const odd = 'é'.repeat(64);
    const res = await post(app.baseUrl, '/session/refresh', {}, { Cookie: `__Secure-refresh_token=${victim['__Secure-refresh_token']}; __Host-refresh_binding=${encodeURIComponent(odd)}`, Origin: ISSUER_ORIGIN });
    assert.equal(res.status, 400);
    assert.equal((await res.json()).error, 'REFRESH_TOKEN_REQUIRED');
});

test('logout via the cookie pair revokes the session and clears both cookies at their paths', async () => {
    const pair = await browserLogin();
    const res = await post(app.baseUrl, '/session/logout', {}, { Cookie: asCookie(pair), Origin: ISSUER_ORIGIN });
    assert.equal(res.status, 200);
    const cleared = res.headers.getSetCookie();
    assert.ok(cleared.some((c) => c.startsWith('__Secure-refresh_token=;') && /Path=\/session(;|$)/i.test(c)), cleared.join(' | '));
    assert.ok(cleared.some((c) => c.startsWith('__Host-refresh_binding=;') && /Path=\/(;|$)/i.test(c)));
    assert.equal((await post(app.baseUrl, '/session/refresh', { refreshToken: pair['__Secure-refresh_token'] })).status, 401);
});

test('mounted under a prefix, the refresh cookie is scoped to <prefix>/session', async () => {
    const bare = express();
    bare.use((_req, _res, next) => { setState(app.state); next(); });
    bare.use(cookieParserLib());
    bare.use(express.json());
    bare.use('/auth', buildRouter({}));
    const server = await new Promise((r) => { const s = bare.listen(0, () => r(s)); });
    try {
        const base = `http://127.0.0.1:${server.address().port}/auth`;
        const email = await registered();
        const res = await post(base, '/login', { email, password });
        const cookie = res.headers.getSetCookie().find((c) => c.startsWith('__Secure-refresh_token='));
        assert.match(cookie, /;\s*Path=\/auth\/session(;|$)/i);
        assert.equal((await post(base, '/session/refresh', {}, { Cookie: asCookie(refreshPair(res)) })).status, 200);
    } finally {
        await new Promise((r) => server.close(r));
    }
});

test('a binding made under a previous tokenHashSecret still matches after rotation', () => {
    const OLD = TEST_SECURITY.tokenHashSecret;
    const NEW = 'rotated-token-hash-secret-0123456789abcdef';
    const before = { config: { cookies: { secure: true }, security: { tokenHashSecret: OLD } } };
    const after = { config: { cookies: { secure: true }, security: { tokenHashSecret: NEW, previousTokenHashSecrets: [OLD] } } };
    const token = 'a'.repeat(128);
    const req = { headers: { cookie: `__Secure-refresh_token=${token}; __Host-refresh_binding=${refreshCookieBinding(before, token)}` }, cookies: { '__Secure-refresh_token': token, '__Host-refresh_binding': refreshCookieBinding(before, token) } };
    assert.equal(readRefreshCookie(after, req), token);
    const forgetful = { config: { cookies: { secure: true }, security: { tokenHashSecret: NEW } } };
    assert.equal(readRefreshCookie(forgetful, req), undefined, 'unbound under the keys it knows: not used');
});

test('discovery advertises /session/end; the old routes are gone', async () => {
    const discovery = await (await fetch(`${app.baseUrl}/.well-known/openid-configuration`)).json();
    assert.equal(discovery.end_session_endpoint, `${ISSUER_ORIGIN}/session/end`);
    for (const path of ['/refresh', '/logout', '/logout/all']) assert.equal((await post(app.baseUrl, path, {})).status, 404, path);
    assert.equal((await fetch(`${app.baseUrl}/oidc/end-session`)).status, 404);
});

// ── review findings (round 4) ────────────────────────────────────────────────

test('a ticket behaves the same whether or not the address has an account (no existence oracle)', async () => {
    await withTemporaryApp({ config: { security: { ...TEST_SECURITY, ...LOCKOUT } } }, async (temp) => {
        const probe = async (email, path) => {
            const { verificationTicket } = await (await post(temp.baseUrl, path, path === '/register' ? { email, password } : { email })).json();
            for (let i = 0; i < 3; i += 1) await post(temp.baseUrl, '/register/verify-email', { email, code: '000000' });
            return (await post(temp.baseUrl, '/register/verify-email', { email, code: '000000', ticket: verificationTicket })).status;
        };
        const active = await registered(temp);
        assert.equal(await probe(active, '/register'), await probe(uniqueEmail('oracle-new'), '/register'), 'register: active vs new');
        const pending = uniqueEmail('oracle-pending');
        await post(temp.baseUrl, '/register', { email: pending, password });
        assert.equal(await probe(pending, '/register/resend-verification'), await probe(uniqueEmail('oracle-unknown'), '/register/resend-verification'), 'resend: pending vs unknown');
    });
});

test('code guesses stay bounded across lock expiry: budgets last the code\'s lifetime whatever is configured', async () => {
    await withTemporaryApp({ config: { security: { ...TEST_SECURITY, verificationCodeLockout: { maxFailedAttempts: 3, windowSeconds: 1, lockSeconds: 1 } } } }, async (temp) => {
        const email = uniqueEmail('bounded');
        await post(temp.baseUrl, '/register', { email, password });
        const { verificationCode } = lastCode(temp, email);
        const wrong = verificationCode === '123456' ? '654321' : '123456';
        for (let i = 0; i < 3; i += 1) await post(temp.baseUrl, '/register/verify-email', { email, code: wrong });
        await new Promise((r) => setTimeout(r, 1500));
        assert.equal((await post(temp.baseUrl, '/register/verify-email', { email, code: verificationCode })).status, 429, 'still locked after the configured 1s');
    });
});

test('a caller holding a live ticket keeps it on resend (a used-up quota can\'t replace it with a dummy)', async () => {
    await withTemporaryApp({ config: { security: { ...TEST_SECURITY, ...LOCKOUT } } }, async (temp) => {
        const email = uniqueEmail('keep-ticket');
        const reg = await post(temp.baseUrl, '/register', { email, password });
        const cookie = ticketCookieOf(reg);
        for (let i = 0; i < 5; i += 1) await post(temp.baseUrl, '/register/resend-verification', { email }); // a stranger uses up the quota
        const mine = await post(temp.baseUrl, '/register/resend-verification', { email }, { Cookie: cookie });
        assert.equal((await mine.json()).verificationTicket, cookie.split('=')[1]);
        await waitForHookCall(temp, 'onVerificationEmailRequested', (c) => c.email === email, { count: 7 });
        // The address budget is locked; the kept ticket still has its own (a wrong code is just wrong).
        await strangerLocks(temp, email, '000000');
        assert.equal((await post(temp.baseUrl, '/register/verify-email', { email, code: '000000' }, { Cookie: cookie })).status, 400);
    });
});

test('the confirmation redirect forwards only logout parameters and never overrides the configured URL\'s', async () => {
    const page = `${ISSUER_ORIGIN}/signout?next=/home`;
    await withTemporaryApp({ config: { oidc: { endSessionConfirmationUrl: page } } }, async (temp) => {
        const u = await loggedIn(temp);
        const res = await fetch(`${temp.baseUrl}/session/end?state=s1&next=https://evil.example&foo=bar&client_id=c1`, { headers: { Cookie: `__Host-access_token=${u.accessToken}` }, redirect: 'manual' });
        const to = new URL(res.headers.get('location'));
        assert.equal(to.searchParams.get('next'), '/home');
        assert.equal(to.searchParams.get('state'), 's1');
        assert.equal(to.searchParams.get('client_id'), 'c1');
        assert.equal(to.searchParams.has('foo'), false);
    });
});

test('a challenge-bound login still has to meet a positive max_age', async () => {
    const c = await rpClient();
    const u = await loggedIn();
    const loginChallenge = await challengeFor(c.clientId, null, { max_age: '1' });
    const bound = await (await post(app.baseUrl, '/login', { email: u.email, password, login_challenge: loginChallenge })).json();
    await new Promise((r) => setTimeout(r, 2100));
    const res = await authorize(c.clientId, bound.accessToken, { max_age: '1', login_challenge: loginChallenge });
    assert.equal(res.status, 401);
    assert.equal((await res.json()).reason, 'max_age');
});

test('cookies.sessionPath pins the refresh cookie path; it must be an absolute path', async () => {
    await withTemporaryApp({ config: { cookies: { sessionPath: '/auth/session' } } }, async (temp) => {
        const email = await registered(temp);
        const res = await post(temp.baseUrl, '/login', { email, password });
        assert.match(res.headers.getSetCookie().find((c) => c.startsWith('__Secure-refresh_token=')), /;\s*Path=\/auth\/session(;|$)/i);
    });
    await assert.rejects(buildTestApp({ config: { cookies: { sessionPath: 'session' } } }), /cookies.sessionPath must be an absolute path/);
});

// ── review findings (round 5) ────────────────────────────────────────────────

test('at most 3 codes per address per code lifetime: later verification emails carry only the link', async () => {
    await withTemporaryApp({}, async (temp) => {
        const email = uniqueEmail('code-cap');
        await post(temp.baseUrl, '/register', { email, password });
        for (let i = 2; i <= 4; i += 1) {
            await post(temp.baseUrl, '/register/resend-verification', { email });
            await waitForHookCall(temp, 'onVerificationEmailRequested', (c) => c.email === email, { count: i });
        }
        const sent = temp.hookCalls.onVerificationEmailRequested.filter((c) => c.email === email);
        assert.deepEqual(sent.map((c) => c.verificationCode === null), [false, false, false, true]);
        assert.ok(sent[3].verificationToken, 'the link is always there');
        assert.equal((await post(temp.baseUrl, '/register/verify-email', { email, token: sent[3].verificationToken })).status, 200);
    });
});

test('a lifetime cap on wrong codes per address holds across tickets — then only the link works', async () => {
    await withTemporaryApp({ config: { security: { ...TEST_SECURITY, verificationCodeLockout: { maxFailedAttempts: 3, windowSeconds: 3600, lockSeconds: 3600, maxTotalFailedAttempts: 4 } } } }, async (temp) => {
        const email = uniqueEmail('lifetime-cap');
        const { verificationTicket: t1 } = await (await post(temp.baseUrl, '/register', { email, password })).json();
        const { verificationTicket: t2 } = await (await post(temp.baseUrl, '/register', { email, password: 'An0ther!Passw0rd' })).json(); // contested: both codes live
        const { verificationCode, verificationToken } = lastCode(temp, email);
        const statuses = [];
        for (const ticket of [t1, t1, t2, t2]) statuses.push((await post(temp.baseUrl, '/register/verify-email', { email, code: '000000', ticket })).status);
        assert.deepEqual(statuses, [400, 400, 400, 429], 'each ticket is within its own budget; the 4th wrong code uses up the address cap');
        const res = await post(temp.baseUrl, '/register/verify-email', { email, code: verificationCode, password: 'An0ther!Passw0rd', ticket: t2 });
        assert.equal(res.status, 429, 'the cap is spent, whatever ticket');
        assert.match((await res.json()).message, /use the link/);
        assert.equal((await post(temp.baseUrl, '/register/verify-email', { email, token: verificationToken, password: 'An0ther!Passw0rd' })).status, 200);
    });
});

test('contested registration: a right code with a wrong password answers like a wrong code', async () => {
    await withTemporaryApp({}, async (temp) => {
        const email = uniqueEmail('contested-oracle');
        const { verificationTicket } = await (await post(temp.baseUrl, '/register', { email, password })).json();
        const { verificationCode } = lastCode(temp, email);
        await post(temp.baseUrl, '/register', { email, password: 'Att4cker!Passw0rd' });
        const wrongPassword = await post(temp.baseUrl, '/register/verify-email', { email, code: verificationCode, password: 'Att4cker!Passw0rd', ticket: verificationTicket });
        const wrongCode = await post(temp.baseUrl, '/register/verify-email', { email, code: '000000', password: 'Att4cker!Passw0rd', ticket: verificationTicket });
        assert.equal(wrongPassword.status, 400);
        assert.deepEqual(await wrongPassword.json(), await wrongCode.json());
        const noPassword = await post(temp.baseUrl, '/register/verify-email', { email, code: verificationCode, ticket: verificationTicket });
        assert.equal((await noPassword.json()).error, 'REGISTRATION_PASSWORD_REQUIRED');
        assert.equal((await post(temp.baseUrl, '/register/verify-email', { email, code: verificationCode, password, ticket: verificationTicket })).status, 200);
    });
});

test('refresh-cookie matching stays cheap and ignores forged extra bindings', async () => {
    const victim = await browserLogin();
    const tokens = Array.from({ length: 100 }, (_, i) => `__Secure-refresh_token=t${i}`).join('; ');
    const bindings = Array.from({ length: 100 }, (_, i) => `__Host-refresh_binding=b${i}`).join('; ');
    const started = process.hrtime.bigint();
    const flood = await post(app.baseUrl, '/session/refresh', {}, { Cookie: `${tokens}; ${bindings}`, Origin: ISSUER_ORIGIN });
    assert.equal(flood.status, 400);
    assert.ok(Number(process.hrtime.bigint() - started) / 1e6 < 1000);
    // Two host-only bindings can't come from a browser: nothing is used.
    const twoBindings = await post(app.baseUrl, '/session/refresh', {}, { Cookie: `${asCookie(victim)}; __Host-refresh_binding=forged`, Origin: ISSUER_ORIGIN });
    assert.equal((await twoBindings.json()).error, 'REFRESH_TOKEN_REQUIRED');
});

test('with cookies.domain, logout clears the cookies even when two bound refresh cookies conflict', async () => {
    await withTemporaryApp({ config: { cookies: { domain: 'idp.test.local', secure: true } } }, async (temp) => {
        const pairOf = async () => {
            const email = await registered(temp);
            const res = await post(temp.baseUrl, '/login', { email, password });
            return res.headers.getSetCookie().filter((c) => /^__Secure-refresh_(token|binding)=/.test(c)).map((c) => c.split(';')[0]).join('; ');
        };
        const res = await post(temp.baseUrl, '/session/logout', {}, { Cookie: `${await pairOf()}; ${await pairOf()}` });
        assert.equal(res.status, 400);
        assert.ok(res.headers.getSetCookie().some((c) => c.startsWith('__Secure-refresh_token=;')));
    });
});

test('an attempt-counter repository missing a method is refused at startup', async () => {
    const storage = stubStorage({ attemptCounterRepository: { recordFailure: async () => ({}), reset: async () => {} } });
    await assert.rejects(buildTestApp({ config: { storage: { factory: async () => storage } } }), /attemptCounterRepository\.get/);
});

test('the in-process attempt counter prunes expired entries as it goes', async () => {
    let now = 0;
    const counters = new MemoryAttemptCounterRepository({ now: () => now });
    for (let i = 0; i < 999; i += 1) await counters.recordFailure(`k${i}`, { max: 5, windowSeconds: 1, lockSeconds: 1 });
    now = 5000;
    await counters.recordFailure('last', { max: 5, windowSeconds: 1, lockSeconds: 1 });
    assert.equal(counters._store.size, 1);
});
