import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { buildTestApp, withTemporaryApp, uniqueEmail } from './helpers/build-test-app.js';
import { verifyAccessToken } from '../src/index.js';

let app;

before(async () => {
    app = await buildTestApp();
});

after(async () => {
    await app.stop();
});

async function requestMagicLink(email) {
    const res = await fetch(`${app.baseUrl}/magic-link/request`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email }),
    });
    assert.equal(res.status, 200);
    const call = app.hookCalls.onMagicLinkRequested.at(-1);
    assert.ok(call && call.email === email, 'onMagicLinkRequested should have fired for this email');
    return call.magicLinkToken;
}

test('magic link: unknown email creates a new passwordless user and logs them in on verify', async () => {
    const email = uniqueEmail('magiclink-new');
    const token = await requestMagicLink(email);

    const verifyRes = await fetch(`${app.baseUrl}/magic-link/verify`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token }),
    });
    const body = await verifyRes.json();
    assert.equal(verifyRes.status, 200, JSON.stringify(body));
    assert.equal(body.isNewUser, true);
    assert.ok(body.accessToken);
    assert.ok(body.refreshToken);

    const claims = await verifyAccessToken(body.accessToken);
    assert.equal(claims.sub, body.userId);
    assert.deepEqual(claims.claims, { role: 'member' });

    // Confirm the account really was created and activated, not just a session floating free.
    const meRes = await fetch(`${app.baseUrl}/me`, { headers: { Authorization: `Bearer ${body.accessToken}` } });
    const me = await meRes.json();
    assert.equal(me.email, email);
    assert.equal(me.status, 'ACTIVE');
});

test('magic link: existing active user logs in via magic link without creating a duplicate account', async () => {
    const email = uniqueEmail('magiclink-existing');
    // Create + activate the user via the normal register/verify flow first.
    await fetch(`${app.baseUrl}/register`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email, password: 'Str0ng!Passw0rd' }) });
    const regCode = app.hookCalls.onVerificationEmailRequested.find((c) => c.email === email).verificationCode;
    await fetch(`${app.baseUrl}/register/verify-email`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email, code: regCode }) });

    const token = await requestMagicLink(email);
    const verifyRes = await fetch(`${app.baseUrl}/magic-link/verify`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token }) });
    const body = await verifyRes.json();
    assert.equal(verifyRes.status, 200, JSON.stringify(body));
    assert.equal(body.isNewUser, false);
    assert.ok(body.accessToken);
});

test('magic link: a token can only be used once', async () => {
    const email = uniqueEmail('magiclink-once');
    const token = await requestMagicLink(email);

    const first = await fetch(`${app.baseUrl}/magic-link/verify`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token }) });
    assert.equal(first.status, 200);

    const second = await fetch(`${app.baseUrl}/magic-link/verify`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token }) });
    assert.equal(second.status, 400);
    assert.equal((await second.json()).error, 'INVALID_OR_EXPIRED_TOKEN');
});

test('magic link: an invalid token is rejected', async () => {
    const res = await fetch(`${app.baseUrl}/magic-link/verify`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token: 'not-a-real-token' }) });
    assert.equal(res.status, 400);
    assert.equal((await res.json()).error, 'INVALID_OR_EXPIRED_TOKEN');
});

test('magic link: signup via magic link can be disabled (invite-only mode)', async () => {
    await withTemporaryApp({ config: { magicLink: { allowSignupViaMagicLink: false } } }, async (noSignupApp) => {
        const email = uniqueEmail('magiclink-invite-only');
        const res = await fetch(`${noSignupApp.baseUrl}/magic-link/request`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email }) });
        assert.equal(res.status, 200); // still enumeration-safe — always 200

        const call = noSignupApp.hookCalls.onMagicLinkRequested.find((c) => c.email === email);
        assert.equal(call, undefined, 'no magic link should be issued for an unknown email when signup-via-magic-link is disabled');

        const stillNoUser = await noSignupApp.state.storage.userRepository.findByEmail(email);
        assert.equal(stillNoUser, null);
    });
});

test('magic link: a suspended account cannot complete login even with a valid token', async () => {
    const email = uniqueEmail('magiclink-suspended');
    const token = await requestMagicLink(email);

    // Activate via first click, then suspend the resulting account before a second request.
    await fetch(`${app.baseUrl}/magic-link/verify`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token }) });
    const user = await app.state.storage.userRepository.findByEmail(email);
    await app.state.storage.userRepository.updateById(user.id, { status: 'SUSPENDED' });

    const secondToken = await requestMagicLink(email);
    const res = await fetch(`${app.baseUrl}/magic-link/verify`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token: secondToken }) });
    assert.equal(res.status, 403);
    assert.equal((await res.json()).error, 'ACCOUNT_SUSPENDED');
});
