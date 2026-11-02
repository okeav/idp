import { test, before, after, mock } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import { generate as generateTotp } from 'otplib';
import { pkcePair } from './helpers/oauth.js';
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

// Closing the limitations left after 0.4.0's second round: the end-session confirmation page, clock
// skew, verification tickets, per-request login challenges and the path-scoped refresh cookie.

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

// ── end-session confirmation page ────────────────────────────────────────────

test('with oidc.endSessionConfirmationUrl, a GET that needs confirmation redirects to that page with its parameters', async () => {
    const page = `${ISSUER_ORIGIN}/signout`;
    await withTemporaryApp({ config: { oidc: { endSessionConfirmationUrl: page } } }, async (temp) => {
        const u = await loggedIn(temp);
        const res = await fetch(`${temp.baseUrl}/session/end?state=abc&ui_locales=de`, { headers: { Cookie: `__Host-access_token=${u.accessToken}` }, redirect: 'manual' });
        assert.equal(res.status, 302);
        const to = new URL(res.headers.get('location'));
        assert.equal(`${to.origin}${to.pathname}`, page);
        assert.equal(to.searchParams.get('state'), 'abc');
        assert.equal(to.searchParams.get('ui_locales'), 'de');
        assert.equal((await fetch(`${temp.baseUrl}/me`, { headers: { Authorization: `Bearer ${u.accessToken}` } })).status, 200, 'nothing ended');
    });
});

test('oidc.endSessionConfirmationUrl must be https and on a trusted origin; IDP_OIDC_END_SESSION_CONFIRMATION_URL sets it', async () => {
    await assert.rejects(buildTestApp({ config: { oidc: { endSessionConfirmationUrl: 'http://idp.test.local/signout' } } }), /must be an https URL/);
    await assert.rejects(buildTestApp({ config: { oidc: { endSessionConfirmationUrl: 'https://elsewhere.example/signout' } } }), /issuer's origin or one of cookies.trustedOrigins/);
    await withTemporaryApp({ config: { cookies: { trustedOrigins: ['https://app.example.com'] }, oidc: { endSessionConfirmationUrl: 'https://app.example.com/signout' } } }, async () => {});
    assert.equal(configFromEnv({ IDP_OIDC_END_SESSION_CONFIRMATION_URL: 'https://idp.example/signout' }).oidc.endSessionConfirmationUrl, 'https://idp.example/signout');
});

// ── clock skew ───────────────────────────────────────────────────────────────

/** A storage factory: the real Mongo adapter, with the database's clock `driftMs` away from this server's. */
const driftingStorage = (driftMs) => async (cfg, deps) => {
    const storage = await createMongoStorage(cfg.mongo, deps);
    storage.databaseTime = async () => ({ time: new Date(Date.now() + driftMs) });
    return storage;
};

function captureLogger() {
    const lines = [];
    const log = (level) => (obj, msg) => lines.push({ level, obj, msg });
    return { lines, logger: { debug: log('debug'), info: log('info'), warn: log('warn'), error: log('error') } };
}

test('startup is refused when this server\'s clock is too far from the database\'s', async () => {
    await assert.rejects(buildTestApp({ config: { storage: { factory: driftingStorage(120_000) } } }), /clock is 120\.0s behind the database's \(limit 30s\)/);
    await assert.rejects(buildTestApp({ config: { storage: { factory: driftingStorage(-45_000) } } }), /ahead of the database's/);
});

test('a skew within the limit but past warnSkewSeconds starts with a warning', async () => {
    const { lines, logger } = captureLogger();
    await withTemporaryApp({ config: { logger, storage: { factory: driftingStorage(5_000) } } }, async () => {
        assert.ok(lines.some((l) => l.level === 'warn' && /behind the database's/.test(l.msg ?? '')));
    });
});

test('the skew is re-checked periodically, and logged as an error once past the limit', async () => {
    mock.timers.enable({ apis: ['setInterval'] });
    try {
        let drift = 0;
        const storage = { databaseTime: async () => ({ time: new Date(Date.now() + drift) }) };
        const { lines, logger } = captureLogger();
        const stop = await startClockSkewGuard(storage, { maxSkewSeconds: 30, warnSkewSeconds: 2, checkIntervalSeconds: 60 }, logger);
        drift = 90_000;
        mock.timers.tick(60_000);
        await new Promise((r) => setImmediate(r));
        assert.ok(lines.some((l) => l.level === 'error' && /behind the database's/.test(l.msg ?? '')), JSON.stringify(lines));
        stop();
    } finally {
        mock.timers.reset();
    }
});

test('checkClockSkew() reports the current skew for health checks; clock settings are validated', async () => {
    const result = await checkClockSkew();
    assert.equal(result.ok, true);
    assert.equal(result.level, 'ok');
    assert.ok(Math.abs(result.skewMs) < 2000);
    await assert.rejects(buildTestApp({ config: { clock: { maxSkewSeconds: 0 } } }), /clock.maxSkewSeconds must be an integer >= 1/);
    await assert.rejects(buildTestApp({ config: { clock: { warnSkewSeconds: 40 } } }), /warnSkewSeconds must not exceed maxSkewSeconds/);
    assert.equal(configFromEnv({ IDP_CLOCK_MAX_SKEW_SECONDS: '10' }).clock.maxSkewSeconds, 10);
});

// ── verification tickets ─────────────────────────────────────────────────────

const LOCKOUT = { verificationCodeLockout: { maxFailedAttempts: 3, windowSeconds: 3600, lockSeconds: 3600 } };
const lastCode = (target, email) => target.hookCalls.onVerificationEmailRequested.filter((c) => c.email === email).at(-1);
const ticketCookieOf = (res) => res.headers.getSetCookie().find((c) => c.startsWith('__Host-verification_ticket=')).split(';')[0];

async function strangerLocks(target, email, code) {
    const wrong = code === '123456' ? '654321' : '123456';
    for (let i = 0; i < 3; i += 1) await post(target.baseUrl, '/register/verify-email', { email, code: wrong });
    assert.equal((await post(target.baseUrl, '/register/verify-email', { email, code })).status, 429, 'the address budget is spent');
}

test('the registering browser verifies with its ticket cookie after a stranger used up the address budget', async () => {
    await withTemporaryApp({ config: { security: { ...TEST_SECURITY, ...LOCKOUT } } }, async (temp) => {
        const email = uniqueEmail('ticket');
        const reg = await post(temp.baseUrl, '/register', { email, password });
        const cookie = ticketCookieOf(reg);
        assert.match(reg.headers.getSetCookie().find((c) => c.startsWith('__Host-verification_ticket=')), /HttpOnly/i);
        const { verificationCode } = lastCode(temp, email);
        await strangerLocks(temp, email, verificationCode);
        const res = await post(temp.baseUrl, '/register/verify-email', { email, code: verificationCode }, { Cookie: cookie });
        assert.equal(res.status, 200);
        assert.ok(res.headers.getSetCookie().some((c) => c.startsWith('__Host-verification_ticket=;')), 'ticket cleared');
        const user = await temp.state.storage.userRepository.findByEmail(email);
        assert.equal(await temp.state.storage.verificationTokenRepository.findActive('verification_ticket', { tokenHash: hashOpaqueToken(temp.state, cookie.split('=')[1], HASH_PURPOSES.EMAIL_VERIFICATION_TICKET) }, user.id), null, 'tickets deleted');
    });
});

test('a ticket has its own budget; a ticket of another account, or a dummy, buys nothing', async () => {
    await withTemporaryApp({ config: { security: { ...TEST_SECURITY, ...LOCKOUT } } }, async (temp) => {
        const victim = uniqueEmail('ticket-victim');
        const { verificationTicket: victimTicket } = await (await post(temp.baseUrl, '/register', { email: victim, password })).json();
        const { verificationCode } = lastCode(temp, victim);
        const wrong = verificationCode === '123456' ? '654321' : '123456';

        // A stranger's tickets: one from their own registration, one (a dummy) from re-registering an active address.
        const { verificationTicket: ownTicket } = await (await post(temp.baseUrl, '/register', { email: uniqueEmail('ticket-attacker'), password })).json();
        const active = await registered(temp);
        const { verificationTicket: dummy } = await (await post(temp.baseUrl, '/register', { email: active, password })).json();
        for (const ticket of [ownTicket, dummy, ownTicket]) await post(temp.baseUrl, '/register/verify-email', { email: victim, code: wrong, ticket });
        assert.equal((await post(temp.baseUrl, '/register/verify-email', { email: victim, code: verificationCode })).status, 429, 'those attempts spent the shared budget');

        // The victim's ticket: three wrong guesses lock it too — its own budget is bounded.
        for (let i = 0; i < 3; i += 1) await post(temp.baseUrl, '/register/verify-email', { email: victim, code: wrong, ticket: victimTicket });
        assert.equal((await post(temp.baseUrl, '/register/verify-email', { email: victim, code: verificationCode, ticket: victimTicket })).status, 429);
        // ...and the link still works.
        assert.equal((await post(temp.baseUrl, '/register/verify-email', { email: victim, token: lastCode(temp, victim).verificationToken })).status, 200);
    });
});

test('at most 5 real tickets per account and code lifetime — more requests get dummies', async () => {
    await withTemporaryApp({ config: { security: { ...TEST_SECURITY, ...LOCKOUT } } }, async (temp) => {
        const email = uniqueEmail('ticket-quota');
        const tickets = [(await (await post(temp.baseUrl, '/register', { email, password })).json()).verificationTicket];
        for (let i = 1; i <= 5; i += 1) {
            tickets.push((await (await post(temp.baseUrl, '/register/resend-verification', { email })).json()).verificationTicket);
            await waitForHookCall(temp, 'onVerificationEmailRequested', (c) => c.email === email, { count: i + 1 });
        }
        const { verificationCode } = lastCode(temp, email);
        await strangerLocks(temp, email, verificationCode);
        assert.equal((await post(temp.baseUrl, '/register/verify-email', { email, code: verificationCode, ticket: tickets[5] })).status, 429, 'the 6th ticket is a dummy');
        assert.equal((await post(temp.baseUrl, '/register/verify-email', { email, code: verificationCode, ticket: tickets[4] })).status, 200, 'the 5th is real');
    });
});

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

test('a planted refresh cookie (no binding, or another session\'s binding) is refused; the real pair refreshes and is rotated', async () => {
    const victim = await browserLogin();
    const attacker = await browserLogin();
    const refresh = (cookie) => post(app.baseUrl, '/session/refresh', {}, { Cookie: cookie, Origin: ISSUER_ORIGIN });

    // What a sibling subdomain can plant: __Secure- (not __Host-) refresh cookies — but not the __Host- binding.
    for (const cookie of [
        `__Secure-refresh_token=${attacker['__Secure-refresh_token']}`,
        `__Secure-refresh_token=${attacker['__Secure-refresh_token']}; __Host-refresh_binding=${victim['__Host-refresh_binding']}`,
    ]) {
        const res = await refresh(cookie);
        assert.equal(res.status, 400, cookie);
        assert.equal((await res.json()).error, 'COOKIE_CONFLICT');
    }

    const ok = await refresh(asCookie(victim));
    assert.equal(ok.status, 200);
    const rotated = refreshPair(ok);
    assert.notEqual(rotated['__Secure-refresh_token'], victim['__Secure-refresh_token']);
    assert.notEqual(rotated['__Host-refresh_binding'], victim['__Host-refresh_binding']);
    assert.equal((await refresh(asCookie(rotated))).status, 200);
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
    assert.throws(() => readRefreshCookie(forgetful, req), /Conflicting session cookies/);
});

test('discovery advertises /session/end; the old routes are gone', async () => {
    const discovery = await (await fetch(`${app.baseUrl}/.well-known/openid-configuration`)).json();
    assert.equal(discovery.end_session_endpoint, `${ISSUER_ORIGIN}/session/end`);
    for (const path of ['/refresh', '/logout', '/logout/all']) assert.equal((await post(app.baseUrl, path, {})).status, 404, path);
    assert.equal((await fetch(`${app.baseUrl}/oidc/end-session`)).status, 404);
});
