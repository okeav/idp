import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { buildTestApp, uniqueEmail } from './helpers/build-test-app.js';
import { createVirtualAuthenticator } from './helpers/virtual-authenticator.js';
import { verifyAccessToken } from '../src/index.js';

const rpID = 'example.com';
const origin = 'https://example.com';

let app;
let authenticator;

before(async () => {
    app = await buildTestApp({ config: { webauthn: { rpID, rpName: 'Test App', origin } } });
    authenticator = createVirtualAuthenticator({ rpID });
});

after(async () => {
    await app.stop();
});

async function registerVerifyLogin(email, password) {
    await fetch(`${app.baseUrl}/register`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email, password }) });
    const code = app.hookCalls.onVerificationEmailRequested.find((c) => c.email === email).verificationCode;
    await fetch(`${app.baseUrl}/register/verify-email`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email, code }) });
    const res = await fetch(`${app.baseUrl}/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email, password }) });
    return res.json();
}

async function registerPasskey(accessToken) {
    const optionsRes = await fetch(`${app.baseUrl}/webauthn/registration/options`, {
        method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${accessToken}` }, body: '{}',
    });
    const options = await optionsRes.json();
    assert.equal(optionsRes.status, 200, JSON.stringify(options));

    const credentialResponse = authenticator.createCredential(options, { origin });

    const verifyRes = await fetch(`${app.baseUrl}/webauthn/registration/verify`, {
        method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${accessToken}` },
        body: JSON.stringify({ response: credentialResponse, name: 'Test Passkey' }),
    });
    const body = await verifyRes.json();
    assert.equal(verifyRes.status, 201, JSON.stringify(body));
    return { credentialId: body.credentialId, credentialResponse };
}

test('WebAuthn registration ceremony stores a real credential', async () => {
    const email = uniqueEmail('webauthn-reg');
    const { accessToken } = await registerVerifyLogin(email, 'Str0ng!Passw0rd');

    const { credentialId } = await registerPasskey(accessToken);
    assert.ok(credentialId);

    const stored = await app.state.storage.credentialRepository.findByCredentialId(credentialId);
    assert.ok(stored);
    assert.equal(stored.counter, 0);
});

test('WebAuthn primary passwordless login: usernameless (discoverable) flow', async () => {
    const email = uniqueEmail('webauthn-primary');
    const { accessToken } = await registerVerifyLogin(email, 'Str0ng!Passw0rd');
    await registerPasskey(accessToken);

    const optionsRes = await fetch(`${app.baseUrl}/webauthn/authentication/options`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
    const options = await optionsRes.json();
    assert.equal(optionsRes.status, 200, JSON.stringify(options));

    const assertionResponse = authenticator.getAssertion(options, { origin });

    const verifyRes = await fetch(`${app.baseUrl}/webauthn/authentication/verify`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ response: assertionResponse }),
    });
    const session = await verifyRes.json();
    assert.equal(verifyRes.status, 200, JSON.stringify(session));
    assert.ok(session.accessToken);
    assert.ok(session.refreshToken);

    const claims = await verifyAccessToken(session.accessToken);
    assert.equal(claims.sub, session.userId);
});

test('WebAuthn primary login: email-scoped options include the registered credential', async () => {
    const email = uniqueEmail('webauthn-scoped');
    const { accessToken } = await registerVerifyLogin(email, 'Str0ng!Passw0rd');
    const { credentialId } = await registerPasskey(accessToken);

    const optionsRes = await fetch(`${app.baseUrl}/webauthn/authentication/options`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email }),
    });
    const options = await optionsRes.json();
    assert.equal(optionsRes.status, 200);
    assert.ok(options.allowCredentials.some((c) => c.id === credentialId));
});

test('WebAuthn: a stale/replayed assertion cannot be used twice (challenge is single-use)', async () => {
    const email = uniqueEmail('webauthn-replay');
    const { accessToken } = await registerVerifyLogin(email, 'Str0ng!Passw0rd');
    await registerPasskey(accessToken);

    const optionsRes = await fetch(`${app.baseUrl}/webauthn/authentication/options`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
    const options = await optionsRes.json();
    const assertionResponse = authenticator.getAssertion(options, { origin });

    const first = await fetch(`${app.baseUrl}/webauthn/authentication/verify`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ response: assertionResponse }) });
    assert.equal(first.status, 200);

    const replay = await fetch(`${app.baseUrl}/webauthn/authentication/verify`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ response: assertionResponse }) });
    assert.equal(replay.status, 400);
    assert.equal((await replay.json()).error, 'WEBAUTHN_CHALLENGE_EXPIRED');
});

test('WebAuthn as MFA second factor: login requires a challenge, passkey completes it instead of TOTP', async () => {
    const email = uniqueEmail('webauthn-mfa');
    const password = 'Str0ng!Passw0rd';
    const { accessToken } = await registerVerifyLogin(email, password);

    // Enable TOTP MFA first — mfaEnabled is only ever toggled on via the TOTP
    // ceremony today; WebAuthn is an *alternative way to complete* the
    // resulting challenge, not an alternative way to turn MFA on.
    const setupRes = await fetch(`${app.baseUrl}/me/mfa/setup`, { method: 'POST', headers: { Authorization: `Bearer ${accessToken}` } });
    const { secret } = await setupRes.json();
    const { generate: generateTotp } = await import('otplib');
    const confirmCode = await generateTotp({ secret });
    await fetch(`${app.baseUrl}/me/mfa/confirm`, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${accessToken}` }, body: JSON.stringify({ code: confirmCode }) });

    // Register a passkey using the still-valid pre-MFA access token.
    await registerPasskey(accessToken);

    // Fresh login now stops at the MFA gate.
    const loginRes = await fetch(`${app.baseUrl}/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email, password }) });
    const loginBody = await loginRes.json();
    assert.equal(loginBody.mfaRequired, true);
    const { mfaChallengeToken } = loginBody;

    const optionsRes = await fetch(`${app.baseUrl}/webauthn/mfa/options`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ mfaChallengeToken }) });
    const options = await optionsRes.json();
    assert.equal(optionsRes.status, 200, JSON.stringify(options));

    const assertionResponse = authenticator.getAssertion(options, { origin });

    const verifyRes = await fetch(`${app.baseUrl}/webauthn/mfa/verify`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ mfaChallengeToken, response: assertionResponse }),
    });
    const session = await verifyRes.json();
    assert.equal(verifyRes.status, 200, JSON.stringify(session));
    assert.ok(session.accessToken);
    assert.ok(session.refreshToken);
});

test('WebAuthn MFA second factor: rejects a credential belonging to a different account even if the challenge happens to match (defense in depth)', async () => {
    const passwordA = 'Str0ng!Passw0rd';
    const emailA = uniqueEmail('webauthn-mfa-victim');
    const { accessToken: tokenA } = await registerVerifyLogin(emailA, passwordA);
    const setupA = await fetch(`${app.baseUrl}/me/mfa/setup`, { method: 'POST', headers: { Authorization: `Bearer ${tokenA}` } });
    const { secret: secretA } = await setupA.json();
    const { generate: generateTotp } = await import('otplib');
    await fetch(`${app.baseUrl}/me/mfa/confirm`, { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${tokenA}` }, body: JSON.stringify({ code: await generateTotp({ secret: secretA }) }) });

    const emailB = uniqueEmail('webauthn-mfa-attacker');
    const { accessToken: tokenB } = await registerVerifyLogin(emailB, 'AnotherStr0ng!Pass');
    await registerPasskey(tokenB); // attacker's own, perfectly legitimate credential

    // Attacker gets their own valid options/assertion for their own credential.
    const attackerOptionsRes = await fetch(`${app.baseUrl}/webauthn/authentication/options`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
    const attackerOptions = await attackerOptionsRes.json();
    const attackerAssertion = authenticator.getAssertion(attackerOptions, { origin });

    // Victim (A) triggers their own MFA challenge via normal login.
    const loginA = await fetch(`${app.baseUrl}/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: emailA, password: passwordA }) });
    const { mfaChallengeToken: victimToken } = await loginA.json();
    const { verifyMfaChallengeToken } = await import('../src/index.js');
    const { sub: victimUserId } = verifyMfaChallengeToken(victimToken);

    // Force the collision this check exists to catch: make victim A's stored
    // MFA-webauthn challenge equal the exact challenge the attacker's
    // assertion actually solves. Without the userId cross-check, this would
    // let the attacker's own credential complete a stranger's MFA gate.
    const { CACHE_KEY_PREFIXES } = await import('../src/config/constants.js');
    await app.state.cache.set(`${CACHE_KEY_PREFIXES.WEBAUTHN_CHALLENGE}:mfa-webauthn:${victimUserId}`, attackerOptions.challenge, 300);

    const verifyRes = await fetch(`${app.baseUrl}/webauthn/mfa/verify`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mfaChallengeToken: victimToken, response: attackerAssertion }),
    });
    assert.equal(verifyRes.status, 401);
    assert.equal((await verifyRes.json()).error, 'WEBAUTHN_VERIFICATION_FAILED');
});
