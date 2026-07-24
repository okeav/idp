import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { generate as generateTotp } from 'otplib';
import { buildTestApp, uniqueEmail } from './helpers/build-test-app.js';
import { verifyAccessToken } from '../src/index.js';

let app;

before(async () => {
    app = await buildTestApp();
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

test('OAuth2 authorization-code flow issues an access token with type "access_token" (regression test)', async () => {
    // 1. Register + approve an OAuth client (relying party).
    const redirectUri = 'https://client.example.com/callback';
    const registerClientRes = await fetch(`${app.baseUrl}/oauth2/clients`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            name: 'Test Client', slug: `test-client-${Date.now()}`,
            redirectUris: [redirectUri], allowedScopes: ['openid', 'email', 'profile'],
        }),
    });
    const client = await registerClientRes.json();
    assert.equal(registerClientRes.status, 201, JSON.stringify(client));

    const approveRes = await fetch(`${app.baseUrl}/oauth2/clients/${client.clientId}/approve`, { method: 'POST' });
    assert.equal(approveRes.status, 200);

    // 2. Log in a resource-owner user.
    const email = uniqueEmail('oauth2user');
    const { accessToken } = await registerVerifyLogin(email, 'Str0ng!Passw0rd');

    // 3. /authorize with no prior consent -> consent_required (not a redirect).
    const authorizeUrl = `${app.baseUrl}/oauth2/authorize?client_id=${client.clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code&scope=openid%20email`;
    const authorizeRes = await fetch(authorizeUrl, { headers: { Authorization: `Bearer ${accessToken}` }, redirect: 'manual' });
    assert.equal(authorizeRes.status, 200);
    const authorizeBody = await authorizeRes.json();
    assert.equal(authorizeBody.action, 'consent_required');

    // 4. Confirm consent -> redirect carrying the authorization code.
    const confirmRes = await fetch(`${app.baseUrl}/oauth2/authorize/confirm`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${accessToken}` },
        body: JSON.stringify({ client_id: client.clientId, redirect_uri: redirectUri, scope: 'openid email' }),
        redirect: 'manual',
    });
    assert.equal(confirmRes.status, 302, await confirmRes.text());
    const location = new URL(confirmRes.headers.get('location'));
    const code = location.searchParams.get('code');
    assert.ok(code, 'redirect should carry an authorization code');

    // 5. Exchange the code for tokens.
    const tokenRes = await fetch(`${app.baseUrl}/oauth2/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            grant_type: 'authorization_code', code,
            redirect_uri: redirectUri, client_id: client.clientId, client_secret: client.clientSecret,
        }),
    });
    const tokenBody = await tokenRes.json();
    assert.equal(tokenRes.status, 200, JSON.stringify(tokenBody));
    assert.ok(tokenBody.access_token);
    assert.ok(tokenBody.id_token, 'openid scope was requested, so an id_token should be issued');

    // Regression test: earlier in this package's history, OAuth2-issued
    // access tokens didn't carry `type: 'access_token'`, so they silently
    // failed authContextMiddleware/verifyAccessToken's type check.
    const claims = await verifyAccessToken(tokenBody.access_token);
    assert.equal(claims.type, 'access_token');
    assert.equal(claims.claims.clientId, client.clientId);
});

test('OAuth2 client_credentials grant issues a machine token with type "access_token" (no refresh token, no user involved)', async () => {
    const registerRes = await fetch(`${app.baseUrl}/oauth2/clients`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            name: 'M2M Client', slug: `m2m-client-${Date.now()}`,
            redirectUris: ['https://client.example.com/callback'],
            allowedScopes: ['reports.read', 'reports.write'],
            allowedGrants: ['client_credentials'],
        }),
    });
    const client = await registerRes.json();
    assert.equal(registerRes.status, 201, JSON.stringify(client));
    await fetch(`${app.baseUrl}/oauth2/clients/${client.clientId}/approve`, { method: 'POST' });

    // No scope requested -> defaults to every scope allowed for the client.
    const tokenRes = await fetch(`${app.baseUrl}/oauth2/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ grant_type: 'client_credentials', client_id: client.clientId, client_secret: client.clientSecret }),
    });
    const tokenBody = await tokenRes.json();
    assert.equal(tokenRes.status, 200, JSON.stringify(tokenBody));
    assert.ok(tokenBody.access_token);
    assert.equal(tokenBody.refresh_token, undefined, 'client_credentials must not issue a refresh token');
    assert.equal(tokenBody.scope, 'reports.read reports.write');

    const claims = await verifyAccessToken(tokenBody.access_token);
    assert.equal(claims.type, 'access_token');
    assert.equal(claims.sub, client.clientId, 'the client itself is the subject of a client_credentials token');
    assert.equal(claims.claims.clientId, client.clientId);

    // Requesting a scope outside allowedScopes is rejected.
    const overreachRes = await fetch(`${app.baseUrl}/oauth2/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ grant_type: 'client_credentials', client_id: client.clientId, client_secret: client.clientSecret, scope: 'reports.read admin.delete' }),
    });
    assert.equal(overreachRes.status, 400);
    assert.equal((await overreachRes.json()).error, 'INVALID_REQUEST');
});

test('allowedGrants is enforced: a client not registered for client_credentials is rejected', async () => {
    const registerRes = await fetch(`${app.baseUrl}/oauth2/clients`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            name: 'Auth-code-only Client', slug: `authcode-only-${Date.now()}`,
            redirectUris: ['https://client.example.com/callback'],
            // allowedGrants omitted -> defaults to authorization_code + refresh_token only.
        }),
    });
    const client = await registerRes.json();
    await fetch(`${app.baseUrl}/oauth2/clients/${client.clientId}/approve`, { method: 'POST' });

    const tokenRes = await fetch(`${app.baseUrl}/oauth2/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ grant_type: 'client_credentials', client_id: client.clientId, client_secret: client.clientSecret }),
    });
    assert.equal(tokenRes.status, 400);
    assert.equal((await tokenRes.json()).error, 'INVALID_REQUEST');
});

test('MFA: setup -> confirm -> login requires challenge -> verify -> full session issued', async () => {
    const email = uniqueEmail('mfauser');
    const password = 'Str0ng!Passw0rd';
    const { accessToken } = await registerVerifyLogin(email, password);

    const setupRes = await fetch(`${app.baseUrl}/me/mfa/setup`, { method: 'POST', headers: { Authorization: `Bearer ${accessToken}` } });
    const setupBody = await setupRes.json();
    assert.equal(setupRes.status, 200, JSON.stringify(setupBody));
    const { secret, otpauthUrl } = setupBody;
    assert.ok(secret);
    assert.match(otpauthUrl, /^otpauth:\/\/totp\//);

    const confirmCode = await generateTotp({ secret });
    const confirmRes = await fetch(`${app.baseUrl}/me/mfa/confirm`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${accessToken}` },
        body: JSON.stringify({ code: confirmCode }),
    });
    const confirmBody = await confirmRes.json();
    assert.equal(confirmRes.status, 200, JSON.stringify(confirmBody));
    assert.equal(confirmBody.mfaEnabled, true);
    assert.ok(Array.isArray(confirmBody.recoveryCodes) && confirmBody.recoveryCodes.length > 0);

    // Logging in now must stop at the MFA challenge, not issue a session directly.
    const loginRes = await fetch(`${app.baseUrl}/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email, password }) });
    assert.equal(loginRes.status, 200);
    const loginBody = await loginRes.json();
    assert.equal(loginBody.mfaRequired, true);
    assert.ok(loginBody.mfaChallengeToken);
    assert.equal(loginBody.accessToken, undefined, 'no session should be issued before the MFA challenge is met');

    const verifyCode = await generateTotp({ secret });
    const verifyRes = await fetch(`${app.baseUrl}/mfa/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mfaChallengeToken: loginBody.mfaChallengeToken, code: verifyCode }),
    });
    const session = await verifyRes.json();
    assert.equal(verifyRes.status, 200, JSON.stringify(session));
    assert.ok(session.accessToken);
    assert.ok(session.refreshToken);

    const claims = await verifyAccessToken(session.accessToken);
    assert.equal(claims.sub, session.userId);
});
