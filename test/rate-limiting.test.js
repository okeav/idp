import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { buildTestApp, withTemporaryApp, uniqueEmail } from './helpers/build-test-app.js';

let app;

before(async () => {
    app = await buildTestApp({
        config: {
            rateLimiting: {
                enabled: true,
                adapter: 'memory',
                login: { max: 3, windowSeconds: 60 },
                loginByEmail: { max: 2, windowSeconds: 60 },
                passwordReset: { max: 2, windowSeconds: 60 },
                mfaChallenge: { max: 2, windowSeconds: 60 },
                refreshToken: { max: 2, windowSeconds: 60 },
            },
        },
    });
});

after(async () => {
    await app.stop();
});

async function login(email, password) {
    return fetch(`${app.baseUrl}/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email, password }) });
}

test('per-email login rate limit trips before the (higher) per-IP limit for repeated attempts against one email', async () => {
    const email = uniqueEmail('ratelimit-email');
    // loginByEmail.max=2 < login(perIP).max=3, so the 3rd attempt against the
    // SAME email is blocked by the email limiter even though the IP limiter
    // alone would still have allowed it.
    const r1 = await login(email, 'wrong-password-1');
    const r2 = await login(email, 'wrong-password-2');
    const r3 = await login(email, 'wrong-password-3');

    assert.equal(r1.status, 401); // INVALID_CREDENTIALS — wrong password, but not yet rate-limited
    assert.equal(r2.status, 401);
    assert.equal(r3.status, 429, 'third attempt against the same email should be blocked by the per-email limit');
    assert.equal((await r3.json()).error, 'RATE_LIMIT_EXCEEDED');
});

test('per-IP login rate limit trips across distinct emails from the same caller', async () => {
    // Each attempt uses a fresh email, so the per-email counter never
    // accumulates past 1 for any single one — only the per-IP counter (which
    // every attempt from this test process shares) can trip here.
    const attempts = await Promise.all(
        Array.from({ length: 3 }, () => login(uniqueEmail('ratelimit-ip'), 'wrong-password'))
    );
    // Requests ran concurrently against a shared in-memory counter — some
    // combination of 401s (real distinct-email attempts, allowed) and a 429
    // once the shared per-IP budget (max 3) is exhausted is expected; the
    // key assertion is that at least one gets rate-limited.
    const statuses = attempts.map((r) => r.status);
    assert.ok(statuses.includes(429), `expected at least one 429 among ${statuses}`);
});

test('password reset request is rate limited per IP', async () => {
    const email = uniqueEmail('ratelimit-reset');
    const request = () => fetch(`${app.baseUrl}/password/forgot`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email }) });

    assert.equal((await request()).status, 200);
    assert.equal((await request()).status, 200);
    const third = await request();
    assert.equal(third.status, 429);
    assert.equal((await third.json()).error, 'RATE_LIMIT_EXCEEDED');
});

test('refresh token endpoint is rate limited per IP', async () => {
    const request = () => fetch(`${app.baseUrl}/refresh`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ refreshToken: 'not-a-real-token' }) });

    const r1 = await request();
    const r2 = await request();
    const r3 = await request();
    assert.equal(r1.status, 401); // REFRESH_TOKEN not valid, but not yet rate-limited
    assert.equal(r2.status, 401);
    assert.equal(r3.status, 429);
});

test('MFA challenge verification is rate limited per IP', async () => {
    const request = () => fetch(`${app.baseUrl}/mfa/verify`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ mfaChallengeToken: 'not-a-real-token', code: '000000' }) });

    const r1 = await request();
    const r2 = await request();
    const r3 = await request();
    assert.equal(r1.status, 401);
    assert.equal(r2.status, 401);
    assert.equal(r3.status, 429);
});

test('rate limiting is a no-op when config.rateLimiting.enabled is false', async () => {
    // helper default is { enabled: false }, so no override needed here — the
    // point is exercising that default explicitly.
    await withTemporaryApp({}, async (disabledApp) => {
        const email = uniqueEmail('no-rate-limit');
        for (let i = 0; i < 15; i++) {
            const res = await fetch(`${disabledApp.baseUrl}/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email, password: 'wrong' }) });
            assert.notEqual(res.status, 429, `attempt ${i + 1} should never be rate-limited when disabled`);
        }
    });
});
