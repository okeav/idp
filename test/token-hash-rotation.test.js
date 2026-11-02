import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import { generate as generateTotp } from 'otplib';
import { buildTestApp, uniqueEmail, waitForHookCall, TEST_SECURITY, testAdminMiddleware } from './helpers/build-test-app.js';
import { serve, json } from './helpers/serve.js';
import { authorizeCode, exchangeCode } from './helpers/oauth.js';
import { initIdentityProvider, configFromEnv } from '../src/index.js';
import { setState } from '../src/config/state.js';
import { hashOpaqueToken, opaqueTokenHashes, HASH_PURPOSES } from '../src/signing/token.service.js';

// security.tokenHashSecret can be rotated (previousTokenHashSecrets), and each kind of stored hash
// is keyed by its own key derived from it.
//
// `app` hashes with the original secret; `rotated` is a second instance on the same database whose
// tokenHashSecret was changed, with the old one listed as previous; `forgetful` changed it WITHOUT
// listing the old one.

const OLD = TEST_SECURITY.tokenHashSecret;
const NEW = 'rotated-token-hash-secret-0123456789abcdef';
const password = 'Str0ng!Passw0rd';
const redirectUri = 'https://rp.example.com/cb';
const ADMIN = { 'x-test-admin': 'yes' };

let app;
let original;
let rotatedState;
let forgetfulState;
let rotated;
let forgetful;

before(async () => {
    app = await buildTestApp();
    const base = app.state.config;
    rotatedState = await initIdentityProvider({ ...base, cache: { adapter: 'memory' }, security: { ...base.security, tokenHashSecret: NEW, previousTokenHashSecrets: [OLD] } });
    forgetfulState = await initIdentityProvider({ ...base, cache: { adapter: 'memory' }, security: { ...base.security, tokenHashSecret: NEW, previousTokenHashSecrets: [] } });
    setState(app.state);
    // Every instance sets its own state per request (the shared app server would use whichever was set last).
    original = await serve({ state: app.state, routerOpts: { clientManagement: { middleware: [testAdminMiddleware] } } });
    rotated = await serve({ state: rotatedState });
    forgetful = await serve({ state: forgetfulState });
});

after(async () => {
    await original.stop();
    await rotated.stop();
    await forgetful.stop();
    await rotatedState.storage.close();
    await forgetfulState.storage.close();
    setState(app.state);
    await app.stop();
});

const post = (base, path, body, headers) => fetch(`${base}${path}`, json(body, headers));

async function registered() {
    const email = uniqueEmail('rot');
    await post(original.baseUrl, '/register', { email, password });
    const code = app.hookCalls.onVerificationEmailRequested.filter((c) => c.email === email).at(-1).verificationCode;
    await post(original.baseUrl, '/register/verify-email', { email, code });
    return { email, ...(await (await post(original.baseUrl, '/login', { email, password })).json()) };
}

test('a refresh token issued under the old secret refreshes after rotation; its successor is hashed under the new one', async () => {
    const u = await registered();
    const res = await post(rotated.baseUrl, '/session/refresh', { refreshToken: u.refreshToken });
    assert.equal(res.status, 200);
    const { refreshToken } = await res.json();
    const row = await rotatedState.storage.sessionRepository.findByRefreshTokenHash(hashOpaqueToken(rotatedState, refreshToken, HASH_PURPOSES.REFRESH_TOKEN));
    assert.ok(row, 'stored under the new key');
    // The old token was rotated: presenting it again is still recognised as reuse.
    assert.equal((await post(rotated.baseUrl, '/session/refresh', { refreshToken: u.refreshToken })).status, 401);
});

test('without the old secret listed, everything hashed under it stops verifying', async () => {
    const u = await registered();
    assert.equal((await post(forgetful.baseUrl, '/session/refresh', { refreshToken: u.refreshToken })).status, 401);
    assert.equal((await post(original.baseUrl, '/session/refresh', { refreshToken: u.refreshToken })).status, 200, 'still a good token');
});

test('logout of an old-secret refresh token works after rotation', async () => {
    const u = await registered();
    assert.equal((await post(rotated.baseUrl, '/session/logout', { refreshToken: u.refreshToken })).status, 200);
    assert.equal((await post(original.baseUrl, '/session/refresh', { refreshToken: u.refreshToken })).status, 401, 'it was revoked');
});

test('email-verification links and codes, reset links and magic links from before the rotation still work', async () => {
    const byLink = uniqueEmail('rot-link');
    await post(original.baseUrl, '/register', { email: byLink, password });
    const { verificationToken } = app.hookCalls.onVerificationEmailRequested.filter((c) => c.email === byLink).at(-1);
    assert.equal((await post(rotated.baseUrl, '/register/verify-email', { email: byLink, token: verificationToken })).status, 200);

    const byCode = uniqueEmail('rot-code');
    await post(original.baseUrl, '/register', { email: byCode, password });
    const { verificationCode } = app.hookCalls.onVerificationEmailRequested.filter((c) => c.email === byCode).at(-1);
    assert.equal((await post(rotated.baseUrl, '/register/verify-email', { email: byCode, code: verificationCode })).status, 200);

    await post(original.baseUrl, '/password/forgot', { email: byLink });
    const { resetToken } = await waitForHookCall(app, 'onPasswordResetRequested', (c) => c.email === byLink);
    assert.equal((await post(rotated.baseUrl, '/password/reset', { email: byLink, token: resetToken, newPassword: 'N3w!Passw0rd' })).status, 200);

    const magic = uniqueEmail('rot-magic');
    await post(original.baseUrl, '/magic-link/request', { email: magic });
    const { magicLinkToken } = app.hookCalls.onMagicLinkRequested.filter((c) => c.email === magic).at(-1);
    assert.equal((await post(rotated.baseUrl, '/magic-link/verify', { token: magicLinkToken })).status, 200);
});

test('an authorization code and a client secret from before the rotation still work; the secret is re-stored under the new key', async () => {
    const u = await registered();
    const c = await (await post(original.baseUrl, '/oauth2/clients', {
        name: 'RP', slug: `rot-${crypto.randomUUID()}`, redirectUris: [redirectUri],
        allowedScopes: ['openid'], allowedGrants: ['authorization_code', 'refresh_token', 'client_credentials'],
    }, ADMIN)).json();
    await fetch(`${original.baseUrl}/oauth2/clients/${c.clientId}/approve`, { method: 'POST', headers: ADMIN });

    const { code, verifier } = await authorizeCode({ baseUrl: original.baseUrl, accessToken: u.accessToken, clientId: c.clientId, redirectUri });
    const exchanged = await exchangeCode({ baseUrl: rotated.baseUrl, client: c, code, redirectUri, verifier });
    assert.equal(exchanged.status, 200, JSON.stringify(exchanged.body));

    // That authentication re-stored the secret under the new key: an instance that knows only the new secret accepts it.
    const machine = (base) => post(base, '/oauth2/token', { grant_type: 'client_credentials', client_id: c.clientId, client_secret: c.clientSecret });
    assert.equal((await machine(forgetful.baseUrl)).status, 200);
});

test('a recovery code generated before the rotation still signs in', async () => {
    const u = await registered();
    const auth = { Authorization: `Bearer ${u.accessToken}` };
    const { secret } = await (await fetch(`${original.baseUrl}/me/mfa/setup`, { method: 'POST', headers: auth })).json();
    const { recoveryCodes } = await (await post(original.baseUrl, '/me/mfa/confirm', { code: await generateTotp({ secret }) }, auth)).json();
    const { mfaChallengeToken } = await (await post(rotated.baseUrl, '/login', { email: u.email, password })).json();
    assert.equal((await post(rotated.baseUrl, '/mfa/verify', { mfaChallengeToken, code: recoveryCodes[0] })).status, 200);
});

test('each purpose has its own key, derived from the secret — no stored hash is keyed by the secret itself', () => {
    const value = 'same-raw-value';
    const hashes = Object.values(HASH_PURPOSES).map((p) => hashOpaqueToken(app.state, value, p));
    assert.equal(new Set(hashes).size, hashes.length);
    assert.ok(!hashes.includes(crypto.createHmac('sha256', OLD).update(value).digest('hex')));
    assert.throws(() => hashOpaqueToken(app.state, value), /Unknown token-hash purpose/);
    assert.deepEqual(opaqueTokenHashes(rotatedState, value, HASH_PURPOSES.MAGIC_LINK), [
        hashOpaqueToken(rotatedState, value, HASH_PURPOSES.MAGIC_LINK),
        hashOpaqueToken(app.state, value, HASH_PURPOSES.MAGIC_LINK),
    ]);
});

test('previousTokenHashSecrets is validated at startup and read from IDP_PREVIOUS_TOKEN_HASH_SECRETS', async () => {
    const security = (previousTokenHashSecrets) => ({ config: { security: { ...TEST_SECURITY, previousTokenHashSecrets } } });
    await assert.rejects(buildTestApp(security(['short'])), /previousTokenHashSecrets\[0\] must be a string of at least 32/);
    await assert.rejects(buildTestApp(security([TEST_SECURITY.tokenHashSecret])), /is the current tokenHashSecret/);
    await assert.rejects(buildTestApp(security([TEST_SECURITY.emailHashPepper])), /must not be the emailHashPepper/);
    await assert.rejects(buildTestApp(security([NEW, NEW])), /duplicates/);
    await assert.rejects(buildTestApp(security('x'.repeat(40))), /must be an array/);
    setState(app.state);
    assert.deepEqual(configFromEnv({ IDP_PREVIOUS_TOKEN_HASH_SECRETS: ` ${NEW} , ${OLD}` }).security.previousTokenHashSecrets, [NEW, OLD]);
});
