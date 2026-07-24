import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { buildTestApp, uniqueEmail } from './helpers/build-test-app.js';

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

test('refresh rotates the token pair and invalidates the old refresh token', async () => {
    const email = uniqueEmail('refresh');
    const { refreshToken: firstRefresh, accessToken: firstAccess } = await registerVerifyLogin(email, 'Str0ng!Passw0rd');

    const refreshRes = await fetch(`${app.baseUrl}/refresh`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refreshToken: firstRefresh }),
    });
    const refreshBody = await refreshRes.json();
    assert.equal(refreshRes.status, 200, JSON.stringify(refreshBody));
    const { accessToken: secondAccess, refreshToken: secondRefresh } = refreshBody;

    assert.notEqual(secondAccess, firstAccess, 'refresh should mint a new access token');
    assert.notEqual(secondRefresh, firstRefresh, 'refresh should rotate to a new refresh token');

    // Reusing the now-rotated-away refresh token must fail.
    const reuseRes = await fetch(`${app.baseUrl}/refresh`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refreshToken: firstRefresh }),
    });
    assert.equal(reuseRes.status, 401);
    assert.equal((await reuseRes.json()).error, 'INVALID_REFRESH_TOKEN');

    // The rotated-to token should still work.
    const followUpRes = await fetch(`${app.baseUrl}/refresh`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refreshToken: secondRefresh }),
    });
    assert.equal(followUpRes.status, 200);
});

test('logout revokes the session; the refresh token fails on next refresh attempt', async () => {
    const email = uniqueEmail('logout');
    const { refreshToken } = await registerVerifyLogin(email, 'Str0ng!Passw0rd');

    const logoutRes = await fetch(`${app.baseUrl}/logout`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refreshToken }),
    });
    assert.equal(logoutRes.status, 200);

    const refreshAfterLogout = await fetch(`${app.baseUrl}/refresh`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refreshToken }),
    });
    assert.equal(refreshAfterLogout.status, 401);
    assert.equal((await refreshAfterLogout.json()).error, 'INVALID_REFRESH_TOKEN');
});

test('logout/all revokes every session for the user', async () => {
    const email = uniqueEmail('logoutall');
    const password = 'Str0ng!Passw0rd';
    const first = await registerVerifyLogin(email, password);
    const secondLoginRes = await fetch(`${app.baseUrl}/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email, password }) });
    const second = await secondLoginRes.json();

    const logoutAllRes = await fetch(`${app.baseUrl}/logout/all`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${first.accessToken}` },
    });
    assert.equal(logoutAllRes.status, 200);

    for (const rt of [first.refreshToken, second.refreshToken]) {
        const res = await fetch(`${app.baseUrl}/refresh`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ refreshToken: rt }) });
        assert.equal(res.status, 401, 'every session should be revoked after logout/all');
    }
});
