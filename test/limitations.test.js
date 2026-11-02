import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { buildTestApp, withTemporaryApp, uniqueEmail } from './helpers/build-test-app.js';
import { json } from './helpers/serve.js';
import crypto from 'crypto';
import { configFromEnv, issueAccessToken } from '../src/index.js';
import { authorizeCode, exchangeCode, pkcePair } from './helpers/oauth.js';
import { gate } from './helpers/gate.js';
import { hashOpaqueToken, opaqueTokenHashes, HASH_PURPOSES } from '../src/signing/token.service.js';
import { revokeAllUserSessions, revokeOtherUserSessions } from '../src/utils/session-family.js';

// The "known limitations" of 0.4.0, fixed.

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
    const email = uniqueEmail('lim');
    await post(target.baseUrl, '/register', { email, password });
    const code = target.hookCalls.onVerificationEmailRequested.filter((c) => c.email === email).at(-1).verificationCode;
    await post(target.baseUrl, '/register/verify-email', { email, code });
    return email;
}

// ── refresh token in JSON bodies ─────────────────────────────────────────────

test('by default a browser login gets the refresh token only as a cookie', async () => {
    const email = await registered();
    for (const headers of [{ Origin: ISSUER_ORIGIN }, { 'Sec-Fetch-Site': 'same-origin' }]) {
        const res = await post(app.baseUrl, '/login', { email, password }, headers);
        assert.equal(res.status, 200, JSON.stringify(headers));
        const body = await res.json();
        assert.equal(body.refreshToken, undefined, JSON.stringify(headers));
        assert.ok(body.accessToken);
        assert.match(res.headers.get('set-cookie') ?? '', /refresh_token=/);
    }
});

test('by default a non-browser login (no Origin, no Sec-Fetch-Site) still gets the refresh token in the body', async () => {
    const email = await registered();
    const body = await (await post(app.baseUrl, '/login', { email, password })).json();
    assert.ok(body.refreshToken);
    const refreshed = await (await post(app.baseUrl, '/refresh', { refreshToken: body.refreshToken })).json();
    assert.ok(refreshed.refreshToken, 'refresh too');
});

test('a browser /refresh by default answers without the refresh token in the body', async () => {
    const email = await registered();
    const { refreshToken } = await (await post(app.baseUrl, '/login', { email, password })).json();
    const res = await post(app.baseUrl, '/refresh', { refreshToken }, { Origin: ISSUER_ORIGIN });
    assert.equal(res.status, 200);
    assert.equal((await res.json()).refreshToken, undefined);
});

test('cookies.refreshTokenInBody: true returns it to browsers too; an unknown value is refused at startup', async () => {
    await withTemporaryApp({ config: { cookies: { refreshTokenInBody: true } } }, async (temp) => {
        const email = await registered(temp);
        const body = await (await post(temp.baseUrl, '/login', { email, password }, { Origin: ISSUER_ORIGIN })).json();
        assert.ok(body.refreshToken);
    });
    await assert.rejects(buildTestApp({ config: { cookies: { refreshTokenInBody: 'yes' } } }), /refreshTokenInBody must be true, false or 'auto'/);
});

test('IDP_COOKIE_REFRESH_TOKEN_IN_BODY: unset or "auto" → auto; true/false as given', () => {
    assert.equal(configFromEnv({}).cookies.refreshTokenInBody, 'auto');
    assert.equal(configFromEnv({ IDP_COOKIE_REFRESH_TOKEN_IN_BODY: 'AUTO' }).cookies.refreshTokenInBody, 'auto');
    assert.equal(configFromEnv({ IDP_COOKIE_REFRESH_TOKEN_IN_BODY: 'false' }).cookies.refreshTokenInBody, false);
    assert.equal(configFromEnv({ IDP_COOKIE_REFRESH_TOKEN_IN_BODY: '1' }).cookies.refreshTokenInBody, true);
});

// ── plain-text MFA secrets ───────────────────────────────────────────────────

test('with an MFA key configured, a plain-text TOTP secret is refused by default', async () => {
    assert.equal(app.state.config.mfa.requireEncrypted, true);
    const email = await registered();
    const { userId } = await (await post(app.baseUrl, '/login', { email, password })).json();
    const { generateSecret } = await import('otplib');
    await app.state.storage.userRepository.updateById(userId, { mfaEnabled: true, mfaSecret: generateSecret(), mfaRecoveryCodes: [] });
    const { mfaChallengeToken } = await (await post(app.baseUrl, '/login', { email, password })).json();
    const res = await post(app.baseUrl, '/mfa/verify', { mfaChallengeToken, code: '123456' });
    assert.equal(res.status, 500);
    assert.equal((await res.json()).error, 'MFA_SECRET_NOT_ENCRYPTED');
});

test('mfa.requireEncrypted: explicit false still opts out; without a key (allowPlaintext) it stays off', async () => {
    await withTemporaryApp({ config: { mfa: { issuerLabel: 'T', encryptionKey: Buffer.alloc(32, 7).toString('base64'), requireEncrypted: false } } }, async (temp) => {
        assert.equal(temp.state.config.mfa.requireEncrypted, false);
    });
    await withTemporaryApp({ config: { mfa: { issuerLabel: 'T', allowPlaintext: true } } }, async (temp) => {
        assert.equal(temp.state.config.mfa.requireEncrypted, false);
    });
    assert.equal(configFromEnv({}).mfa.requireEncrypted, undefined, 'unset env → the key-dependent default');
});

// ── end-session confirmation ─────────────────────────────────────────────────

async function signedIn() {
    const email = await registered();
    return (await (await post(app.baseUrl, '/login', { email, password })).json()).accessToken;
}
const sessionCookie = (token) => ({ Cookie: `__Host-access_token=${token}` });
const meStatus = async (token) => (await fetch(`${app.baseUrl}/me`, { headers: { Authorization: `Bearer ${token}` } })).status;

test('GET /oidc/end-session without an id_token_hint asks for confirmation and ends nothing', async () => {
    const token = await signedIn();
    // What a cross-site <img src> or top-level link would send.
    const res = await fetch(`${app.baseUrl}/oidc/end-session`, { headers: { ...sessionCookie(token), 'Sec-Fetch-Site': 'cross-site' } });
    assert.equal(res.status, 200);
    assert.deepEqual(await res.json(), { action: 'logout_confirmation_required' });
    assert.equal(res.headers.getSetCookie().length, 0, 'no cookie cleared');
    assert.equal(await meStatus(token), 200);
});

test('the confirmation is a POST from a trusted origin — JSON or an HTML form', async () => {
    const a = await signedIn();
    const confirmed = await fetch(`${app.baseUrl}/oidc/end-session`, { method: 'POST', headers: { ...sessionCookie(a), Origin: ISSUER_ORIGIN, 'Sec-Fetch-Site': 'same-origin' } });
    assert.equal(confirmed.status, 200);
    assert.equal(await meStatus(a), 401);

    const b = await signedIn();
    const form = await fetch(`${app.baseUrl}/oidc/end-session`, { method: 'POST', body: new URLSearchParams({ state: 'x' }), headers: { ...sessionCookie(b), Origin: ISSUER_ORIGIN } });
    assert.equal(form.status, 200);
    assert.equal(await meStatus(b), 401);
});

test('a cross-origin POST to /oidc/end-session is refused', async () => {
    const token = await signedIn();
    const res = await fetch(`${app.baseUrl}/oidc/end-session`, { method: 'POST', headers: { ...sessionCookie(token), Origin: 'https://evil.example', 'Sec-Fetch-Site': 'cross-site' } });
    assert.equal(res.status, 403);
    assert.equal(await meStatus(token), 200);
});

// ── prompt and max_age ───────────────────────────────────────────────────────

const redirectUri = 'https://rp.example.com/cb';

async function rpClient() {
    const c = await (await post(app.baseUrl, '/oauth2/clients', {
        name: 'RP', slug: `lim-${crypto.randomUUID()}`, redirectUris: [redirectUri],
        allowedScopes: ['openid', 'email'], allowedGrants: ['authorization_code', 'refresh_token'],
    }, { 'x-test-admin': 'yes' })).json();
    await fetch(`${app.baseUrl}/oauth2/clients/${c.clientId}/approve`, { method: 'POST', headers: { 'x-test-admin': 'yes' } });
    return c;
}

function authorize(clientId, token, extra = {}) {
    const { challenge } = pkcePair();
    const qs = new URLSearchParams({ client_id: clientId, redirect_uri: redirectUri, response_type: 'code', scope: 'openid', code_challenge: challenge, code_challenge_method: 'S256', state: 'st', ...extra });
    return fetch(`${app.baseUrl}/oauth2/authorize?${qs}`, { headers: token ? { Authorization: `Bearer ${token}` } : {}, redirect: 'manual' });
}

/** A token for a fresh user whose login happened `ageSeconds` ago (or with no auth_time at all). */
async function tokenAged(ageSeconds) {
    const email = await registered();
    const { userId } = await (await post(app.baseUrl, '/login', { email, password })).json();
    const opts = ageSeconds === null ? {} : { authTime: Math.floor(Date.now() / 1000) - ageSeconds };
    return (await issueAccessToken({ sub: userId, email, claims: {} }, opts)).token;
}

const redirected = (res) => new URL(res.headers.get('location'));

test('prompt=none never shows UI: login_required / consent_required go back to the client', async () => {
    const c = await rpClient();
    const anon = await authorize(c.clientId, null, { prompt: 'none' });
    assert.equal(anon.status, 302);
    assert.equal(redirected(anon).origin + redirected(anon).pathname, redirectUri);
    assert.equal(redirected(anon).searchParams.get('error'), 'login_required');
    assert.equal(redirected(anon).searchParams.get('state'), 'st');
    assert.equal(redirected(anon).searchParams.get('iss'), ISSUER_ORIGIN);

    const token = await tokenAged(5);
    const noConsent = await authorize(c.clientId, token, { prompt: 'none' });
    assert.equal(noConsent.status, 302);
    assert.equal(redirected(noConsent).searchParams.get('error'), 'consent_required');

    // With consent on file, prompt=none issues the code silently.
    await authorizeCode({ baseUrl: app.baseUrl, accessToken: token, clientId: c.clientId, redirectUri });
    const silent = await authorize(c.clientId, token, { prompt: 'none' });
    assert.equal(silent.status, 302);
    assert.ok(redirected(silent).searchParams.get('code'));
});

test('prompt=login (and select_account, max_age=0) requires a login made just now', async () => {
    const c = await rpClient();
    const stale = await tokenAged(10 * 60);
    for (const extra of [{ prompt: 'login' }, { prompt: 'select_account' }, { max_age: '0' }]) {
        const res = await authorize(c.clientId, stale, extra);
        assert.equal(res.status, 401, JSON.stringify(extra));
        assert.deepEqual(await res.json(), { action: 'login_required', reason: 'prompt_login' });
    }
    // The IdP page signs the user in, then repeats the request: now it goes through.
    const fresh = await tokenAged(2);
    const res = await authorize(c.clientId, fresh, { prompt: 'login' });
    assert.equal(res.status, 200);
    assert.equal((await res.json()).action, 'consent_required');
});

test('max_age: a login older than max_age, or of unknown age, must be repeated', async () => {
    const c = await rpClient();
    const tenMinutes = await tokenAged(10 * 60);
    const tooOld = await authorize(c.clientId, tenMinutes, { max_age: '300' });
    assert.equal(tooOld.status, 401);
    assert.equal((await tooOld.json()).reason, 'max_age');
    assert.equal((await authorize(c.clientId, tenMinutes, { max_age: '3600' })).status, 200);
    const unknown = await authorize(c.clientId, await tokenAged(null), { max_age: '3600' });
    assert.equal(unknown.status, 401);
    assert.equal((await authorize(c.clientId, tenMinutes, { max_age: '-1' })).status, 400);
});

test('prompt=consent shows the consent screen even when consent is on file', async () => {
    const c = await rpClient();
    const token = await tokenAged(5);
    await authorizeCode({ baseUrl: app.baseUrl, accessToken: token, clientId: c.clientId, redirectUri });
    assert.equal((await authorize(c.clientId, token)).status, 302, 'consent on file: straight through');
    const res = await authorize(c.clientId, token, { prompt: 'consent' });
    assert.equal(res.status, 200);
    assert.equal((await res.json()).action, 'consent_required');
});

test('unknown prompt values, or none combined with another, are refused; discovery lists the supported ones', async () => {
    const c = await rpClient();
    const token = await tokenAged(5);
    assert.equal((await authorize(c.clientId, token, { prompt: 'bogus' })).status, 400);
    assert.equal((await authorize(c.clientId, token, { prompt: 'none login' })).status, 400);
    const discovery = await (await fetch(`${app.baseUrl}/.well-known/openid-configuration`)).json();
    assert.deepEqual(discovery.prompt_values_supported, ['none', 'login', 'consent', 'select_account']);
});

// ── ordering that doesn't depend on the app servers' clocks ──────────────────

/** Runs `fn` as an app server whose clock is `ms` off (what a second, unsynced instance would write). */
async function withClockOffset(ms, fn) {
    const Real = Date;
    class Skewed extends Real {
        constructor(...args) {
            if (args.length) super(...args);
            else super(Real.now() + ms);
        }
        static now() { return Real.now() + ms; }
    }
    globalThis.Date = Skewed;
    try {
        return await fn();
    } finally {
        globalThis.Date = Real;
    }
}

const jtiOf = (jwt) => JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString()).jti;

async function loggedIn(target = app) {
    const email = await registered(target);
    return { email, ...(await (await post(target.baseUrl, '/login', { email, password })).json()) };
}

test('a refresh racing "sign out everywhere" on a server whose clock is behind still ends', async () => {
    const u = await loggedIn();
    const g = gate(app.state.storage.sessionRepository.model, 'create', { when: 'before' });
    const refreshing = post(app.baseUrl, '/refresh', { refreshToken: u.refreshToken });
    await g.reached;
    g.restore();
    await withClockOffset(-5 * 60_000, () => revokeAllUserSessions(app.state, u.userId));
    g.release();
    assert.equal((await refreshing).status, 401);
});

test('a code issued before "sign out everywhere" (on a server whose clock is behind) is refused', async () => {
    const u = await loggedIn();
    const c = await rpClient();
    // A sessionless token: no authorizing session whose revocation would refuse the code on its own.
    const { token } = await issueAccessToken({ sub: u.userId, email: u.email, claims: {} });
    const { code, verifier } = await authorizeCode({ baseUrl: app.baseUrl, accessToken: token, clientId: c.clientId, redirectUri });
    await withClockOffset(-5 * 60_000, () => revokeAllUserSessions(app.state, u.userId));
    assert.equal((await exchangeCode({ baseUrl: app.baseUrl, client: c, code, redirectUri, verifier })).status, 400);
});

test('a code issued before its consent was revoked and granted again (on a server whose clock is behind) is refused', async () => {
    const u = await loggedIn();
    const c = await rpClient();
    await authorizeCode({ baseUrl: app.baseUrl, accessToken: u.accessToken, clientId: c.clientId, redirectUri });
    const { code, verifier } = await authorizeCode({ baseUrl: app.baseUrl, accessToken: u.accessToken, clientId: c.clientId, redirectUri });
    await withClockOffset(-5 * 60_000, async () => {
        await app.state.storage.consentRepository.revoke(u.userId, c.clientId);
        await app.state.storage.consentRepository.upsert(u.userId, c.clientId, ['openid']);
    });
    assert.equal((await exchangeCode({ baseUrl: app.baseUrl, client: c, code, redirectUri, verifier })).status, 400);
});

test('the rotation time the reuse grace period is measured from is the database\'s, not the rotating server\'s', async () => {
    // A server whose clock ran ahead used to stamp the rotation in the future, so a replay of the old
    // token stayed "within the grace period" — and unpunished — for as long as the clocks disagreed.
    const u = await loggedIn();
    await withClockOffset(5 * 60_000, () => post(app.baseUrl, '/refresh', { refreshToken: u.refreshToken }));
    const row = await app.state.storage.sessionRepository.findByRefreshTokenHash(hashOpaqueToken(app.state, u.refreshToken, HASH_PURPOSES.REFRESH_TOKEN));
    assert.equal(row.revokeReason, 'rotated');
    assert.ok(Math.abs(new Date(row.revokedAt).getTime() - Date.now()) < 60_000, `revokedAt ${new Date(row.revokedAt).toISOString()}`);
});

test('a replay after the grace period revokes the family (grace measured by the database)', async () => {
    await withTemporaryApp({ config: { session: { refreshReuseGraceSeconds: 1 } } }, async (temp) => {
        const u = await loggedIn(temp);
        const rotated = await (await post(temp.baseUrl, '/refresh', { refreshToken: u.refreshToken })).json();
        assert.equal((await post(temp.baseUrl, '/refresh', { refreshToken: u.refreshToken })).status, 401, 'replay within the grace: refused');
        assert.ok(await temp.state.storage.sessionRepository.rotatedWithin(hashOpaqueToken(temp.state, u.refreshToken, HASH_PURPOSES.REFRESH_TOKEN), 1));
        await new Promise((r) => setTimeout(r, 1500));
        assert.equal((await post(temp.baseUrl, '/refresh', { refreshToken: u.refreshToken })).status, 401, 'the replay');
        assert.equal((await post(temp.baseUrl, '/refresh', { refreshToken: rotated.refreshToken })).status, 401, 'the family was revoked');
    });
});

test('the session exempted by "sign out other sessions" survives it repeatedly; the others do not', async () => {
    const keep = await loggedIn();
    const other = await (await post(app.baseUrl, '/login', { email: keep.email, password })).json();
    await revokeOtherUserSessions(app.state, keep.userId, { exceptJti: jtiOf(keep.accessToken) });
    const once = await (await post(app.baseUrl, '/refresh', { refreshToken: keep.refreshToken })).json();
    assert.ok(once.refreshToken);
    await revokeOtherUserSessions(app.state, keep.userId, { exceptJti: jtiOf(once.accessToken) });
    await revokeOtherUserSessions(app.state, keep.userId, { exceptJti: jtiOf(once.accessToken) });
    assert.equal((await post(app.baseUrl, '/refresh', { refreshToken: once.refreshToken })).status, 200);
    assert.equal((await post(app.baseUrl, '/refresh', { refreshToken: other.refreshToken })).status, 401);
});

// ── review findings ──────────────────────────────────────────────────────────

test('end-session recognises the browser session from the refresh cookie alone (access cookie expired)', async () => {
    const email = await registered();
    const login = await post(app.baseUrl, '/login', { email, password }, { Origin: ISSUER_ORIGIN });
    const refreshCookie = login.headers.getSetCookie().find((c) => c.includes('refresh_token=')).split(';')[0];

    const asked = await fetch(`${app.baseUrl}/oidc/end-session`, { headers: { Cookie: refreshCookie } });
    assert.deepEqual(await asked.json(), { action: 'logout_confirmation_required' });
    assert.equal((await post(app.baseUrl, '/refresh', {}, { Cookie: refreshCookie, Origin: ISSUER_ORIGIN })).status, 200, 'the GET ended nothing');

    // That refresh rotated the cookie: use the new one.
    const again = await post(app.baseUrl, '/login', { email, password }, { Origin: ISSUER_ORIGIN });
    const live = again.headers.getSetCookie().find((c) => c.includes('refresh_token=')).split(';')[0];
    const confirmed = await post(app.baseUrl, '/oidc/end-session', {}, { Cookie: live, Origin: ISSUER_ORIGIN });
    assert.equal(confirmed.status, 200);
    assert.ok(confirmed.headers.getSetCookie().some((c) => c.startsWith('__Host-refresh_token=;')), 'cookies cleared');
    assert.equal((await post(app.baseUrl, '/refresh', {}, { Cookie: live, Origin: ISSUER_ORIGIN })).status, 401, 'the session ended');
});

async function mfaUser() {
    const u = await loggedIn();
    const auth = { Authorization: `Bearer ${u.accessToken}` };
    const { secret } = await (await fetch(`${app.baseUrl}/me/mfa/setup`, { method: 'POST', headers: auth })).json();
    const { generate } = await import('otplib');
    const { recoveryCodes } = await (await post(app.baseUrl, '/me/mfa/confirm', { code: await generate({ secret }) }, auth)).json();
    return { ...u, recoveryCodes };
}

test('an MFA challenge from before "sign out everywhere" is refused — no clock involved', async () => {
    const u = await mfaUser();
    const { mfaChallengeToken } = await (await post(app.baseUrl, '/login', { email: u.email, password })).json();
    await revokeAllUserSessions(app.state, u.userId);
    const res = await post(app.baseUrl, '/mfa/verify', { mfaChallengeToken, code: u.recoveryCodes[0] });
    assert.equal(res.status, 401);
    assert.equal((await res.json()).error, 'INVALID_MFA_CHALLENGE_TOKEN');
    // A challenge issued after it completes normally.
    const fresh = (await (await post(app.baseUrl, '/login', { email: u.email, password })).json()).mfaChallengeToken;
    assert.equal((await post(app.baseUrl, '/mfa/verify', { mfaChallengeToken: fresh, code: u.recoveryCodes[1] })).status, 200);
});

test('an MFA challenge is refused after "sign out everywhere" even on a server whose clock is behind', async () => {
    const u = await mfaUser();
    const { mfaChallengeToken } = await (await post(app.baseUrl, '/login', { email: u.email, password })).json();
    await withClockOffset(-10_000, () => revokeAllUserSessions(app.state, u.userId));
    assert.equal((await post(app.baseUrl, '/mfa/verify', { mfaChallengeToken, code: u.recoveryCodes[0] })).status, 401);
});

test('/oauth2/authorize with an empty scope list is a 400, not a 500', async () => {
    const c = await rpClient();
    const token = await tokenAged(5);
    for (const extra of [{ scope: ' ' }, { scope: ' ', prompt: 'none' }]) {
        const res = await authorize(c.clientId, token, extra);
        assert.equal(res.status, 400, JSON.stringify(extra));
    }
});

test('an adapter that does not return sessionEpoch or consent version fails closed', async () => {
    await withTemporaryApp({}, async (temp) => {
        const email = await registered(temp);
        const users = temp.state.storage.userRepository;
        const findById = users.findById.bind(users);
        users.findById = async (...args) => {
            const u = await findById(...args);
            return u ? Object.assign(u.toObject ? u.toObject() : { ...u }, { id: String(u.id ?? u._id), sessionEpoch: undefined }) : u;
        };
        try {
            assert.equal((await post(temp.baseUrl, '/login', { email, password })).status, 401);
        } finally {
            users.findById = findById;
        }
    });
});
