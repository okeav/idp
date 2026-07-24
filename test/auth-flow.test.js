import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { buildTestApp, uniqueEmail } from './helpers/build-test-app.js';
import { issueAccessToken, issueMfaChallengeToken, verifyAccessToken } from '../src/index.js';

let app;

before(async () => {
    app = await buildTestApp();
});

after(async () => {
    await app.stop();
});

test('register -> verify email -> login -> receives access + refresh tokens', async () => {
    const email = uniqueEmail('register');
    const password = 'Str0ng!Passw0rd';

    const registerRes = await fetch(`${app.baseUrl}/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password, firstName: 'Ada', lastName: 'Lovelace' }),
    });
    assert.equal(registerRes.status, 201);

    // No real mailer — read the verification code straight off the captured hook call.
    const verificationCall = app.hookCalls.onVerificationEmailRequested.find((c) => c.email === email);
    assert.ok(verificationCall, 'onVerificationEmailRequested should have fired for this email');
    assert.ok(verificationCall.verificationCode, 'hook payload should include a verification code');

    const verifyRes = await fetch(`${app.baseUrl}/register/verify-email`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, code: verificationCall.verificationCode }),
    });
    assert.equal(verifyRes.status, 200);

    const loginRes = await fetch(`${app.baseUrl}/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
    });
    const body = await loginRes.json();
    assert.equal(loginRes.status, 200, JSON.stringify(body));

    assert.ok(body.accessToken, 'login response should include an access token');
    assert.ok(body.refreshToken, 'login response should include a refresh token');
    assert.ok(body.userId);

    // The claims resolved by the test app's resolveAuthContext hook should
    // round-trip onto the issued access token.
    const claims = await verifyAccessToken(body.accessToken);
    assert.equal(claims.sub, body.userId);
    assert.deepEqual(claims.claims, { role: 'member' });
});

test('registering with an already-registered email does not reveal that fact', async () => {
    const email = uniqueEmail('dup');
    const password = 'Str0ng!Passw0rd';

    const first = await fetch(`${app.baseUrl}/register`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
    });
    const second = await fetch(`${app.baseUrl}/register`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
    });

    assert.equal(first.status, second.status);
    assert.deepEqual(await first.json(), await second.json());
});

test('login before verifying email is rejected', async () => {
    const email = uniqueEmail('unverified');
    const password = 'Str0ng!Passw0rd';
    await fetch(`${app.baseUrl}/register`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
    });

    const loginRes = await fetch(`${app.baseUrl}/login`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
    });
    assert.equal(loginRes.status, 403);
    const body = await loginRes.json();
    assert.equal(body.error, 'PENDING_VERIFICATION');
});

test('verifyAccessToken succeeds on a token this IDP issued', async () => {
    const { token } = await issueAccessToken({ sub: 'user-123', email: 'x@example.com', claims: { role: 'member' } });
    const claims = await verifyAccessToken(token);
    assert.equal(claims.sub, 'user-123');
    assert.equal(claims.type, 'access_token');
});

test('verifyAccessToken rejects an expired token', async () => {
    // Must exceed the 30s clockTolerance verifyAccessToken applies for clock-skew
    // tolerance, or this would still verify successfully.
    const { token } = await issueAccessToken({ sub: 'user-123' }, { ttlSeconds: -3600 });
    await assert.rejects(() => verifyAccessToken(token), (err) => {
        assert.equal(err.code, 'TOKEN_EXPIRED');
        return true;
    });
});

test('verifyAccessToken rejects a tampered token', async () => {
    const { token } = await issueAccessToken({ sub: 'user-123' });
    const parts = token.split('.');
    // Flip a character in the middle of the signature — same length, invalid
    // signature. (Not the last character: in base64url, a signature's final
    // char can carry as few as 2 significant bits, so some flips there decode
    // to the exact same signature bytes and the "tampered" token still verifies.)
    const sig = parts[2];
    const mid = Math.floor(sig.length / 2);
    const flippedChar = sig[mid] === 'A' ? 'B' : 'A';
    const flipped = sig.slice(0, mid) + flippedChar + sig.slice(mid + 1);
    const tampered = `${parts[0]}.${parts[1]}.${flipped}`;

    await assert.rejects(() => verifyAccessToken(tampered), (err) => {
        assert.equal(err.code, 'INVALID_TOKEN');
        return true;
    });
});

test('verifyAccessToken rejects a token of the wrong type', async () => {
    const mfaToken = await issueMfaChallengeToken('user-123');
    await assert.rejects(() => verifyAccessToken(mfaToken), (err) => {
        assert.equal(err.code, 'INVALID_TOKEN');
        return true;
    });
});

test('authContextMiddleware accepts a Bearer access token and populates req.auth', async () => {
    const email = uniqueEmail('bearer');
    const password = 'Str0ng!Passw0rd';
    await fetch(`${app.baseUrl}/register`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email, password }) });
    const code = app.hookCalls.onVerificationEmailRequested.find((c) => c.email === email).verificationCode;
    await fetch(`${app.baseUrl}/register/verify-email`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email, code }) });
    const loginRes = await fetch(`${app.baseUrl}/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email, password }) });
    const { accessToken } = await loginRes.json();

    const meRes = await fetch(`${app.baseUrl}/me`, { headers: { Authorization: `Bearer ${accessToken}` } });
    assert.equal(meRes.status, 200);
    const me = await meRes.json();
    assert.equal(me.email, email);
});

