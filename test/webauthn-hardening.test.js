import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { generate as generateTotp } from 'otplib';
import { buildTestApp, withTemporaryApp, uniqueEmail } from './helpers/build-test-app.js';
import { createVirtualAuthenticator } from './helpers/virtual-authenticator.js';
import { json } from './helpers/serve.js';
import { MemoryCacheAdapter } from '../src/cache/memory.adapter.js';

// Step-up and WebAuthn issues found in the 0.3.0 audit:
//  - a session alone (no recent login) could register a passkey — a permanent
//    login that outlives logout-all and password reset — or enrol MFA, or
//    delete the account; there was no way to list or remove passkeys;
//  - primary passkey login didn't explicitly require user verification, the
//    discoverable user handle wasn't checked, the challenge was get-then-del
//    and the counter write unconditional (both raceable);
//  - email-scoped options listed an account's credential ids to anyone.

const rpID = 'example.com';
const origin = 'https://example.com';
const password = 'Str0ng!Passw0rd';

let app;
let authenticator;

before(async () => {
    app = await buildTestApp({ config: { webauthn: { rpID, rpName: 'Test App', origin } } });
    authenticator = createVirtualAuthenticator({ rpID });
});

after(async () => {
    await app.stop();
});

const post = (path, body, headers) => fetch(`${app.baseUrl}${path}`, json(body, headers));
const bearer = (t) => ({ Authorization: `Bearer ${t}` });
const payloadOf = (jwtToken) => JSON.parse(Buffer.from(jwtToken.split('.')[1], 'base64url').toString());

async function registerVerifyLogin(email = uniqueEmail('wa')) {
    await post('/register', { email, password });
    const code = app.hookCalls.onVerificationEmailRequested.filter((c) => c.email === email).at(-1).verificationCode;
    await post('/register/verify-email', { email, code });
    return { email, ...(await (await post('/login', { email, password })).json()) };
}

async function registerPasskey(accessToken, { userVerified = true } = {}) {
    const options = await (await post('/webauthn/registration/options', {}, bearer(accessToken))).json();
    const res = await post('/webauthn/registration/verify', { response: authenticator.createCredential(options, { origin, userVerified }), name: 'Key' }, bearer(accessToken));
    return { status: res.status, body: await res.json() };
}

async function passkeyLogin(assertionOpts = {}) {
    const options = await (await post('/webauthn/authentication/options', {})).json();
    const response = authenticator.getAssertion(options, { origin, ...assertionOpts });
    const res = await post('/webauthn/authentication/verify', { response });
    return { status: res.status, body: await res.json() };
}

/** Runs `fn` with recent-auth so short that every login is already stale. */
async function withStaleLogins(fn) {
    const saved = app.state.config.session.recentAuthMaxAgeSeconds;
    app.state.config.session.recentAuthMaxAgeSeconds = 1;
    try {
        await new Promise((r) => setTimeout(r, 2100));
        await fn();
    } finally {
        app.state.config.session.recentAuthMaxAgeSeconds = saved;
    }
}

test('step-up: a session whose login is not recent cannot add a passkey, enrol MFA, or delete the account', async () => {
    const user = await registerVerifyLogin();
    await withStaleLogins(async () => {
        for (const [method, path, body] of [
            ['POST', '/webauthn/registration/options', {}],
            ['POST', '/me/mfa/setup', undefined],
            ['POST', '/me/mfa/confirm', { code: '123456' }],
            ['DELETE', '/me', undefined],
        ]) {
            const res = await fetch(`${app.baseUrl}${path}`, { method, headers: { 'Content-Type': 'application/json', ...bearer(user.accessToken) }, ...(body ? { body: JSON.stringify(body) } : {}) });
            assert.equal(res.status, 401, `${method} ${path}`);
            assert.equal((await res.json()).error, 'REAUTHENTICATION_REQUIRED', `${method} ${path}`);
        }
        // Reading is still fine.
        assert.equal((await fetch(`${app.baseUrl}/me`, { headers: bearer(user.accessToken) })).status, 200);
    });
    const me = await (await fetch(`${app.baseUrl}/me`, { headers: bearer(user.accessToken) })).json();
    assert.equal(me.status, 'ACTIVE', 'the account was not deleted');
});

test('step-up: a refresh does not make a login recent — auth_time carries over', async () => {
    const user = await registerVerifyLogin();
    const original = payloadOf(user.accessToken).auth_time;
    assert.ok(Number.isInteger(original));

    await new Promise((r) => setTimeout(r, 1100));
    const refreshed = await (await post('/session/refresh', { refreshToken: user.refreshToken })).json();
    assert.equal(payloadOf(refreshed.accessToken).auth_time, original);

    await withStaleLogins(async () => {
        const res = await post('/webauthn/registration/options', {}, bearer(refreshed.accessToken));
        assert.equal((await res.json()).error, 'REAUTHENTICATION_REQUIRED');
    });

    // A fresh login is recent again.
    const fresh = await (await post('/login', { email: user.email, password })).json();
    assert.equal((await post('/webauthn/registration/options', {}, bearer(fresh.accessToken))).status, 200);
});

test('passkeys: the owner can list and delete them; another account cannot touch them', async () => {
    const owner = await registerVerifyLogin();
    const { body: reg } = await registerPasskey(owner.accessToken);
    const other = await registerVerifyLogin();

    const list = await (await fetch(`${app.baseUrl}/me/passkeys`, { headers: bearer(owner.accessToken) })).json();
    assert.deepEqual(list.map((p) => p.credentialId), [reg.credentialId]);
    assert.equal(list[0].publicKey, undefined);

    const foreign = await fetch(`${app.baseUrl}/me/passkeys/${encodeURIComponent(reg.credentialId)}`, { method: 'DELETE', headers: bearer(other.accessToken) });
    assert.equal(foreign.status, 404);
    assert.ok(await app.state.storage.credentialRepository.findByCredentialId(reg.credentialId));

    const own = await fetch(`${app.baseUrl}/me/passkeys/${encodeURIComponent(reg.credentialId)}`, { method: 'DELETE', headers: bearer(owner.accessToken) });
    assert.equal(own.status, 200);
    assert.equal(await app.state.storage.credentialRepository.findByCredentialId(reg.credentialId), null);
    assert.equal((await passkeyLogin({ credentialId: reg.credentialId })).body.error, 'CREDENTIAL_NOT_FOUND', 'a deleted passkey no longer logs in');
});

test('primary passkey login requires user verification; registration does too', async () => {
    const user = await registerVerifyLogin();
    const noUvReg = await registerPasskey(user.accessToken, { userVerified: false });
    assert.equal(noUvReg.status, 400);
    assert.equal(noUvReg.body.error, 'WEBAUTHN_VERIFICATION_FAILED');

    const { body: reg } = await registerPasskey(user.accessToken);
    const noUv = await passkeyLogin({ credentialId: reg.credentialId, userVerified: false });
    assert.equal(noUv.status, 400);
    assert.equal(noUv.body.error, 'WEBAUTHN_VERIFICATION_FAILED');
    assert.equal((await passkeyLogin({ credentialId: reg.credentialId })).status, 200);
});

test('a passkey as the SECOND factor works without user verification (PIN-less security key)', async () => {
    const user = await registerVerifyLogin();
    const { body: reg } = await registerPasskey(user.accessToken);
    // Enable TOTP so login stops at the MFA challenge.
    const { secret } = await (await fetch(`${app.baseUrl}/me/mfa/setup`, { method: 'POST', headers: bearer(user.accessToken) })).json();
    assert.equal((await post('/me/mfa/confirm', { code: await generateTotp({ secret }) }, bearer(user.accessToken))).status, 200);

    const { mfaChallengeToken } = await (await post('/login', { email: user.email, password })).json();
    const options = await (await post('/webauthn/mfa/options', { mfaChallengeToken })).json();
    const res = await post('/webauthn/mfa/verify', { mfaChallengeToken, response: authenticator.getAssertion(options, { origin, credentialId: reg.credentialId, userVerified: false }) });
    assert.equal(res.status, 200, await res.text());
});

test('a discoverable assertion whose user handle names a different account is refused', async () => {
    const user = await registerVerifyLogin();
    const { body: reg } = await registerPasskey(user.accessToken);
    const other = await registerVerifyLogin();

    const forged = await passkeyLogin({ credentialId: reg.credentialId, userHandle: Buffer.from(String(other.userId)).toString('base64url') });
    assert.equal(forged.status, 400);
    assert.equal(forged.body.error, 'WEBAUTHN_VERIFICATION_FAILED');

    const genuine = await passkeyLogin({ credentialId: reg.credentialId, userHandle: Buffer.from(String(user.userId)).toString('base64url') });
    assert.equal(genuine.status, 200);
    assert.equal(genuine.body.userId, user.userId);
});

test('one assertion submitted twice concurrently logs in once (single-use challenge)', async () => {
    const user = await registerVerifyLogin();
    const { body: reg } = await registerPasskey(user.accessToken);
    const options = await (await post('/webauthn/authentication/options', {})).json();
    const response = authenticator.getAssertion(options, { origin, credentialId: reg.credentialId });
    const statuses = await Promise.all([1, 2, 3].map(async () => (await post('/webauthn/authentication/verify', { response })).status));
    assert.deepEqual(statuses.sort(), [200, 400, 400]);
});

test('a cloned authenticator: two assertions with the same counter, concurrently — only one gets in', async () => {
    const user = await registerVerifyLogin();
    const { body: reg } = await registerPasskey(user.accessToken);
    const responses = [];
    for (let i = 0; i < 3; i += 1) {
        const options = await (await post('/webauthn/authentication/options', {})).json();
        responses.push(authenticator.getAssertion(options, { origin, credentialId: reg.credentialId, counter: 7 }));
    }
    const statuses = await Promise.all(responses.map(async (response) => (await post('/webauthn/authentication/verify', { response })).status));
    assert.deepEqual(statuses.sort(), [200, 400, 400]);
    assert.equal((await app.state.storage.credentialRepository.findByCredentialId(reg.credentialId)).counter, 7);
});

test('passkey login options are rate limited per IP', async () => {
    await withTemporaryApp({ config: { webauthn: { rpID, rpName: 'T', origin }, rateLimiting: { enabled: true, webauthnAuthentication: { max: 2, windowSeconds: 60 } } } }, async (temp) => {
        const opt = () => fetch(`${temp.baseUrl}/webauthn/authentication/options`, json({}));
        assert.equal((await opt()).status, 200);
        assert.equal((await opt()).status, 200);
        const third = await opt();
        assert.equal(third.status, 429);
        assert.equal((await third.json()).error, 'RATE_LIMIT_EXCEEDED');
    });
});

test('allowCredentialsByEmail: an unknown address gets a stable decoy, never an empty list', async () => {
    app.state.config.webauthn.allowCredentialsByEmail = true;
    try {
        const ask = async (email) => (await (await post('/webauthn/authentication/options', { email })).json()).allowCredentials;
        const nobody = uniqueEmail('nobody');
        const first = await ask(nobody);
        assert.equal(first.length, 1);
        assert.deepEqual(await ask(nobody), first, 'stable across requests');
        assert.notDeepEqual(await ask(uniqueEmail('someone-else')), first);
    } finally {
        delete app.state.config.webauthn.allowCredentialsByEmail;
    }
});

test('MemoryCacheAdapter.take: returns a value once, and nothing once expired', async () => {
    const cache = new MemoryCacheAdapter();
    try {
        await cache.set('k', 'v', 60);
        const [a, b] = await Promise.all([cache.take('k'), cache.take('k')]);
        assert.deepEqual([a, b].sort(), [null, 'v'].sort());
        await cache.set('gone', 'v', -1);
        assert.equal(await cache.take('gone'), null);
    } finally {
        cache.close();
    }
});
