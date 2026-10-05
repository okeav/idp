import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { buildTestApp, uniqueEmail } from './helpers/build-test-app.js';
import { serve, json } from './helpers/serve.js';
import { initIdentityProvider, issueAccessToken } from '../src/index.js';
import { setState } from '../src/config/state.js';
import { CACHE_KEY_PREFIXES } from '../src/config/constants.js';

// Issue: the access-token revocation cache is per process, so "log out
// everywhere" and password reset/change left access tokens valid on every
// OTHER instance until they expired.
//
// Two instances here = two initIdentityProvider() states, each with its own
// in-memory cache and Mongo connection, sharing one database.

let app;
let stateA;
let stateB;
let instanceA;
let instanceB;
const password = 'Str0ng!Passw0rd';

before(async () => {
    app = await buildTestApp();
    stateA = app.state;
    stateB = await initIdentityProvider({ ...stateA.config, cache: { adapter: 'memory' } });
    setState(stateA);
    assert.notEqual(stateA.cache, stateB.cache);
    instanceA = await serve({ state: stateA, routerOpts: {} });
    instanceB = await serve({ state: stateB, routerOpts: {} });
});

after(async () => {
    await instanceA.stop();
    await instanceB.stop();
    await stateB.storage.close();
    setState(stateA);
    await app.stop();
});

async function registerVerifyLogin(email) {
    await fetch(`${instanceA.baseUrl}/register`, json({ email, password }));
    const code = app.hookCalls.onVerificationEmailRequested.find((c) => c.email === email).verificationCode;
    await fetch(`${instanceA.baseUrl}/register/verify-email`, json({ email, code }));
    return login(instanceA, email);
}

async function login(instance, email, pw = password) {
    const res = await fetch(`${instance.baseUrl}/login`, json({ email, password: pw }));
    const body = await res.json();
    assert.equal(res.status, 200, JSON.stringify(body));
    return body;
}

const me = (instance, accessToken) => fetch(`${instance.baseUrl}/me`, { headers: { Authorization: `Bearer ${accessToken}` } });
const refresh = (instance, refreshToken) => fetch(`${instance.baseUrl}/refresh`, json({ refreshToken }));

async function assertRefused(res, label) {
    const body = await res.json();
    assert.equal(res.status, 401, `${label}: ${JSON.stringify(body)}`);
}

test('after logout-all on instance A, an existing access token is refused on instance B (and A); refresh is refused too', async () => {
    const email = uniqueEmail('logout-all');
    const first = await registerVerifyLogin(email);
    const second = await login(instanceB, email); // a second device, logged in via B

    assert.equal((await me(instanceB, first.accessToken)).status, 200, 'tokens work across instances before logout');

    const out = await fetch(`${instanceA.baseUrl}/logout/all`, { method: 'POST', headers: { Authorization: `Bearer ${first.accessToken}` } });
    assert.equal(out.status, 200);

    await assertRefused(await me(instanceB, first.accessToken), 'B, first device');
    await assertRefused(await me(instanceB, second.accessToken), 'B, second device');
    await assertRefused(await me(instanceA, second.accessToken), 'A, second device');
    await assertRefused(await refresh(instanceB, first.refreshToken), 'refresh on B');
    await assertRefused(await refresh(instanceA, second.refreshToken), 'refresh on A');
});

test('after a password reset, existing access tokens are refused on the other instance; refresh is refused too', async () => {
    const email = uniqueEmail('reset');
    const session = await registerVerifyLogin(email);

    await fetch(`${instanceA.baseUrl}/password/forgot`, json({ email }));
    const { resetToken } = app.hookCalls.onPasswordResetRequested.find((c) => c.email === email);
    const reset = await fetch(`${instanceA.baseUrl}/password/reset`, json({ email, token: resetToken, newPassword: 'N3w!Passw0rdX' }));
    assert.equal(reset.status, 200, await reset.text());

    await assertRefused(await me(instanceB, session.accessToken), 'B after reset');
    await assertRefused(await me(instanceA, session.accessToken), 'A after reset');
    await assertRefused(await refresh(instanceB, session.refreshToken), 'refresh on B after reset');
});

test('after a password change on B, the other device\'s access token is refused on A', async () => {
    const email = uniqueEmail('change');
    const laptop = await registerVerifyLogin(email);
    const phone = await login(instanceA, email);

    const change = await fetch(`${instanceB.baseUrl}/password/change`, json({ currentPassword: password, newPassword: 'N3w!Passw0rdY' }, { Authorization: `Bearer ${laptop.accessToken}` }));
    assert.equal(change.status, 200, await change.text());

    await assertRefused(await me(instanceA, phone.accessToken), 'phone on A');
    await assertRefused(await refresh(instanceA, phone.refreshToken), 'phone refresh on A');
});

test('revoking one session refuses its access token on the other instance, and leaves the others alone', async () => {
    const email = uniqueEmail('revoke-one');
    const keep = await registerVerifyLogin(email);
    const kill = await login(instanceA, email);

    const sessions = await (await fetch(`${instanceA.baseUrl}/me/sessions`, { headers: { Authorization: `Bearer ${keep.accessToken}` } })).json();
    const killRow = await stateA.storage.sessionRepository.findByRefreshTokenHash(
        (await import('../src/signing/token.service.js')).hashOpaqueToken(stateA, kill.refreshToken),
    );
    assert.ok(sessions.some((s) => String(s.id) === String(killRow.id)));
    const del = await fetch(`${instanceA.baseUrl}/me/sessions/${killRow.id}`, { method: 'DELETE', headers: { Authorization: `Bearer ${keep.accessToken}` } });
    assert.equal(del.status, 200);

    await assertRefused(await me(instanceB, kill.accessToken), 'revoked session on B');
    assert.equal((await me(instanceB, keep.accessToken)).status, 200, 'the other session is untouched');
});

test('control: with session.verifyOnEachRequest off, the other instance only has its own cache (the documented trade-off)', async () => {
    const email = uniqueEmail('opt-out');
    const session = await registerVerifyLogin(email);
    stateA.config.session.verifyOnEachRequest = false;
    stateB.config.session.verifyOnEachRequest = false;
    try {
        await fetch(`${instanceA.baseUrl}/logout/all`, { method: 'POST', headers: { Authorization: `Bearer ${session.accessToken}` } });
        assert.equal((await me(instanceB, session.accessToken)).status, 200, 'without the per-request check the token lives on until expiry');
        await assertRefused(await refresh(instanceB, session.refreshToken), 'refresh still checks storage');
    } finally {
        stateA.config.session.verifyOnEachRequest = true;
        stateB.config.session.verifyOnEachRequest = true;
    }
});

test('a cache "not revoked" never skips the storage check; a cache "revoked" short-circuits', async () => {
    const email = uniqueEmail('cache');
    const session = await registerVerifyLogin(email);
    const { jti } = (await (await import('../src/index.js')).verifyAccessToken(session.accessToken));

    // Cache says revoked, storage says live → refused without asking storage.
    let storageCalls = 0;
    const realFind = stateB.storage.sessionRepository.findByJti.bind(stateB.storage.sessionRepository);
    stateB.storage.sessionRepository.findByJti = async (j) => { storageCalls += 1; return realFind(j); };
    try {
        await stateB.cache.set(`${CACHE_KEY_PREFIXES.REVOKED_REFRESH_TOKEN}:${jti}`, '1', 60);
        await assertRefused(await me(instanceB, session.accessToken), 'cache-revoked');
        assert.equal(storageCalls, 0, 'cache "revoked" short-circuits');
        await stateB.cache.del(`${CACHE_KEY_PREFIXES.REVOKED_REFRESH_TOKEN}:${jti}`);

        assert.equal((await me(instanceB, session.accessToken)).status, 200);
        assert.equal(storageCalls, 1, 'a cache miss still goes to storage');

        // Revoke directly in storage (as another instance would) — the cache
        // knows nothing, and the token is refused anyway.
        await stateA.storage.sessionRepository.revokeAllForUser(session.userId);
        await assertRefused(await me(instanceB, session.accessToken), 'storage-revoked, cache unaware');
    } finally {
        stateB.storage.sessionRepository.findByJti = realFind;
    }
});

test('cache outage: verifyOnEachRequest falls through to storage; storage outage fails closed (503)', async () => {
    const email = uniqueEmail('outage');
    const session = await registerVerifyLogin(email);

    const cache = stateB.cache;
    stateB.cache = { ...cache, get: async () => { throw new Error('redis down'); } };
    try {
        assert.equal((await me(instanceB, session.accessToken)).status, 200, 'the session store is authoritative; the cache is only a fast path');
    } finally {
        stateB.cache = cache;
    }

    const repo = stateB.storage.sessionRepository;
    const realFind = repo.findByJti;
    repo.findByJti = async () => { throw new Error('db down'); };
    try {
        const res = await me(instanceB, session.accessToken);
        assert.equal(res.status, 503);
        assert.equal((await res.json()).error, 'SESSION_STORE_UNAVAILABLE');
    } finally {
        repo.findByJti = realFind;
    }
});

test('tokens without a session row: refused unless marked sessionless (client_credentials, the public issueAccessToken export)', async () => {
    const email = uniqueEmail('sessionless');
    const { userId } = await registerVerifyLogin(email);

    setState(stateA);
    const sessionless = await issueAccessToken({ sub: userId, email });
    assert.equal((await me(instanceB, sessionless.token)).status, 200);

    const tokenService = await import('../src/signing/token.service.js');
    const orphan = await tokenService.issueAccessToken(stateA, { sub: userId, email }); // session-bound, but no session row
    await assertRefused(await me(instanceB, orphan.token), 'a session-bound token with no session row');
});

test('OAuth2 access tokens: authorization-code tokens are revocable through their session; client_credentials tokens pass', async () => {
    const admin = { 'x-test-admin': 'yes' };
    const redirectUri = 'https://client.example.com/callback';
    const client = await (await fetch(`${app.baseUrl}/oauth2/clients`, json({
        name: 'RP', slug: `rp-${Date.now()}`, redirectUris: [redirectUri], allowedScopes: ['openid', 'email'],
        allowedGrants: ['authorization_code', 'refresh_token', 'client_credentials'],
    }, admin))).json();
    await fetch(`${app.baseUrl}/oauth2/clients/${client.clientId}/approve`, { method: 'POST', headers: admin });

    const cc = await (await fetch(`${instanceA.baseUrl}/oauth2/token`, json({ grant_type: 'client_credentials', client_id: client.clientId, client_secret: client.clientSecret, scope: 'email' }))).json();
    const introspect = await fetch(`${instanceB.baseUrl}/oauth2/token/introspect`, json({ token: 'x' }, { Authorization: `Bearer ${cc.access_token}` }));
    assert.equal(introspect.status, 200, 'a client_credentials token has no session and must still authenticate');

    const user = await registerVerifyLogin(uniqueEmail('oauth-user'));
    const confirm = await fetch(`${instanceA.baseUrl}/oauth2/authorize/confirm`, {
        ...json({ client_id: client.clientId, redirect_uri: redirectUri, scope: 'openid email' }, { Authorization: `Bearer ${user.accessToken}` }),
        redirect: 'manual',
    });
    const code = new URL(confirm.headers.get('location')).searchParams.get('code');
    const tokens = await (await fetch(`${instanceA.baseUrl}/oauth2/token`, json({ grant_type: 'authorization_code', code, redirect_uri: redirectUri, client_id: client.clientId, client_secret: client.clientSecret }))).json();
    const userinfo = () => fetch(`${instanceB.baseUrl}/userinfo`, { headers: { Authorization: `Bearer ${tokens.access_token}` } });
    assert.equal((await userinfo()).status, 200);

    await fetch(`${instanceA.baseUrl}/logout/all`, { method: 'POST', headers: { Authorization: `Bearer ${user.accessToken}` } });
    await assertRefused(await userinfo(), 'RP access token after the user logged out everywhere');
});
