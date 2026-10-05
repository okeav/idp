import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { generate as generateTotp, verify as verifyTotp } from 'otplib';
import { buildTestApp, uniqueEmail } from './helpers/build-test-app.js';
import { createVirtualAuthenticator } from './helpers/virtual-authenticator.js';
import { serve, json } from './helpers/serve.js';
import { MemoryAttemptCounterRepository } from '../src/mfa/memory-attempt-counter.js';
import { enforceRateLimit } from '../src/rate-limit/enforce.js';

// Issue: second-factor attempts were limited per IP only, so an attacker
// holding the password could spread guesses at the 6-digit code across IPs.

const rpID = 'example.com';
const origin = 'https://example.com';
const password = 'Str0ng!Passw0rd';

let app;
let server; // trusts X-Forwarded-For, so each request can come from a "different IP"
let authenticator;
let ipSeq = 0;
const nextIp = () => {
    ipSeq += 1;
    return `10.${(ipSeq >> 16) & 255}.${(ipSeq >> 8) & 255}.${ipSeq & 255}`;
};

before(async () => {
    app = await buildTestApp({
        config: {
            webauthn: { rpID, rpName: 'Test App', origin },
            // The per-IP limits are real here (5 MFA attempts per IP per 15
            // min) — the attack is precisely that rotating IPs sidesteps them.
            rateLimiting: { enabled: true, login: { max: 10_000 }, loginByEmail: { max: 10_000 } },
        },
    });
    server = await serve({ trustProxy: true });
    authenticator = createVirtualAuthenticator({ rpID });
});

after(async () => {
    await server.stop();
    await app.stop();
});

function post(path, body, headers = {}) {
    return fetch(`${server.baseUrl}${path}`, json(body, { 'X-Forwarded-For': nextIp(), ...headers }));
}

async function registerVerifyLogin(email) {
    await fetch(`${app.baseUrl}/register`, json({ email, password }));
    const code = app.hookCalls.onVerificationEmailRequested.find((c) => c.email === email).verificationCode;
    await fetch(`${app.baseUrl}/register/verify-email`, json({ email, code }));
    return (await post('/login', { email, password })).json();
}

async function userWithMfa(prefix) {
    const email = uniqueEmail(prefix);
    const { accessToken, userId } = await registerVerifyLogin(email);
    const auth = { Authorization: `Bearer ${accessToken}` };
    const { secret } = await (await fetch(`${server.baseUrl}/me/mfa/setup`, { method: 'POST', headers: auth })).json();
    const confirm = await post('/me/mfa/confirm', { code: await generateTotp({ secret }) }, auth);
    const { recoveryCodes } = await confirm.json();
    assert.equal(confirm.status, 200);
    return { email, userId, secret, recoveryCodes, accessToken };
}

async function challenge(email) {
    const { mfaChallengeToken } = await (await post('/login', { email, password })).json();
    assert.ok(mfaChallengeToken);
    return mfaChallengeToken;
}

/** A 6-digit code guaranteed not to verify (outside the ±30s tolerance too). */
async function wrongCode(secret) {
    for (let n = 0; ; n += 1) {
        const candidate = String((Number(await generateTotp({ secret })) + 123457 + n) % 1000000).padStart(6, '0');
        if (!(await verifyTotp({ token: candidate, secret, epochTolerance: 30 })).valid) return candidate;
    }
}

const mfaLockedEvents = (userId) => app.hookCalls.onAuditLog.filter((e) => e.action === 'MFA_LOCKED' && e.userId === String(userId));

test('5 wrong codes from 5 different IPs lock the account; a 6th from yet another IP is refused even with the RIGHT code', async () => {
    const { email, userId, secret } = await userWithMfa('lock-ips');
    const token = await challenge(email);

    for (let i = 1; i <= 4; i += 1) {
        const res = await post('/mfa/verify', { mfaChallengeToken: token, code: await wrongCode(secret) });
        assert.equal(res.status, 400, `attempt ${i}`);
        assert.equal((await res.json()).error, 'INVALID_MFA_CODE');
    }
    const fifth = await post('/mfa/verify', { mfaChallengeToken: token, code: await wrongCode(secret) });
    assert.equal(fifth.status, 429);
    assert.equal((await fifth.json()).error, 'MFA_LOCKED');

    const rightCode = await post('/mfa/verify', { mfaChallengeToken: token, code: await generateTotp({ secret }) });
    const wrongAgain = await post('/mfa/verify', { mfaChallengeToken: token, code: await wrongCode(secret) });
    const rightBody = await rightCode.json();
    assert.equal(rightCode.status, 429, 'the lockout is not lifted by the right code');
    assert.equal(rightBody.accessToken, undefined);
    assert.deepEqual(rightBody, await wrongAgain.json(), 'locked responses must not hint whether the code was right');
    assert.equal(wrongAgain.status, 429);

    // A fresh login (new challenge token) doesn't reset the per-account lock.
    const fresh = await post('/mfa/verify', { mfaChallengeToken: await challenge(email), code: await generateTotp({ secret }) });
    assert.equal(fresh.status, 429);

    const events = mfaLockedEvents(userId);
    assert.equal(events.length, 1, 'MFA_LOCKED is emitted once per lockout');
    assert.equal(events[0].failedAttempts, 5);
    assert.ok(events[0].lockedUntil);
});

test('recovery codes count toward the same limit, and a valid recovery code is not consumed while locked', async () => {
    const { email, userId, secret, recoveryCodes } = await userWithMfa('lock-recovery');

    // Recovery codes are XXXXXX-XXXXXX (13 chars): /mfa/verify must accept
    // them at all (its schema used to cap `code` at 10 characters).
    const accepted = await post('/mfa/verify', { mfaChallengeToken: await challenge(email), code: recoveryCodes[1] });
    assert.equal(accepted.status, 200, await accepted.text());

    const token = await challenge(email);

    for (let i = 0; i < 2; i += 1) {
        assert.equal((await post('/mfa/verify', { mfaChallengeToken: token, code: await wrongCode(secret) })).status, 400);
    }
    for (let i = 0; i < 2; i += 1) {
        assert.equal((await post('/mfa/verify', { mfaChallengeToken: token, code: `ABCDE${i}-FFFFFF` })).status, 400);
    }
    const fifth = await post('/mfa/verify', { mfaChallengeToken: token, code: 'ZZZZZZ-ZZZZZZ' });
    assert.equal(fifth.status, 429);

    const withRecovery = await post('/mfa/verify', { mfaChallengeToken: token, code: recoveryCodes[0] });
    assert.equal(withRecovery.status, 429);
    const user = await app.state.storage.userRepository.findById(userId, { select: '+mfaRecoveryCodes' });
    assert.equal(user.mfaRecoveryCodes[0].usedAt, null, 'no recovery code may be burned by a locked attempt');
    assert.ok(user.mfaRecoveryCodes[1].usedAt, 'the one used successfully earlier is spent');
    assert.equal(user.mfaRecoveryCodes.filter((rc) => rc.usedAt).length, 1);
});

test('WebAuthn-as-MFA failures count toward the same per-account limit, and a valid assertion is refused while locked', async () => {
    const { email, secret, accessToken } = await userWithMfa('lock-webauthn');

    // Register a passkey on the account.
    const auth = { Authorization: `Bearer ${accessToken}` };
    const regOptions = await (await post('/webauthn/registration/options', {}, auth)).json();
    const reg = await post('/webauthn/registration/verify', { response: authenticator.createCredential(regOptions, { origin }), name: 'Key' }, auth);
    assert.equal(reg.status, 201, await reg.text());

    const token = await challenge(email);
    for (let i = 0; i < 3; i += 1) {
        assert.equal((await post('/mfa/verify', { mfaChallengeToken: token, code: await wrongCode(secret) })).status, 400);
    }
    // Failed assertion: a credential id that doesn't exist.
    await post('/webauthn/mfa/options', { mfaChallengeToken: token });
    const bogus = await post('/webauthn/mfa/verify', { mfaChallengeToken: token, response: { id: 'not-a-real-credential', rawId: 'x', type: 'public-key', response: {} } });
    assert.equal(bogus.status, 400);

    // Fifth failure — also over WebAuthn — triggers the lock.
    await post('/webauthn/mfa/options', { mfaChallengeToken: token });
    const fifth = await post('/webauthn/mfa/verify', { mfaChallengeToken: token, response: { id: 'still-not-real', rawId: 'x', type: 'public-key', response: {} } });
    assert.equal(fifth.status, 429);
    assert.equal((await fifth.json()).error, 'MFA_LOCKED');

    // A genuine assertion from the registered passkey is refused while locked…
    const options = await (await post('/webauthn/mfa/options', { mfaChallengeToken: token })).json();
    const genuine = await post('/webauthn/mfa/verify', { mfaChallengeToken: token, response: authenticator.getAssertion(options, { origin }) });
    assert.equal(genuine.status, 429);
    // …and so is TOTP.
    assert.equal((await post('/mfa/verify', { mfaChallengeToken: token, code: await generateTotp({ secret }) })).status, 429);
});

test('a successful verify resets the counter', async () => {
    const { email, secret } = await userWithMfa('lock-reset');
    for (let round = 0; round < 2; round += 1) {
        const token = await challenge(email);
        for (let i = 0; i < 4; i += 1) {
            assert.equal((await post('/mfa/verify', { mfaChallengeToken: token, code: await wrongCode(secret) })).status, 400, `round ${round}, attempt ${i}`);
        }
        const ok = await post('/mfa/verify', { mfaChallengeToken: token, code: await generateTotp({ secret }) });
        assert.equal(ok.status, 200, `round ${round}: 4 failures + success must never lock, since success resets`);
    }
});

test('the lock lifts after lockSeconds, and the count starts over after windowSeconds', async () => {
    const { email, secret } = await userWithMfa('lock-window');
    const lockout = app.state.config.mfa.lockout;
    const saved = { ...lockout };
    Object.assign(lockout, { windowSeconds: 1, lockSeconds: 1 });
    try {
        const token = await challenge(email);
        for (let i = 0; i < 4; i += 1) await post('/mfa/verify', { mfaChallengeToken: token, code: await wrongCode(secret) });
        assert.equal((await post('/mfa/verify', { mfaChallengeToken: token, code: await wrongCode(secret) })).status, 429);
        assert.equal((await post('/mfa/verify', { mfaChallengeToken: token, code: await generateTotp({ secret }) })).status, 429);

        await new Promise((r) => setTimeout(r, 1200));
        const after = await post('/mfa/verify', { mfaChallengeToken: await challenge(email), code: await generateTotp({ secret }) });
        assert.equal(after.status, 200, 'unlocked once lockSeconds has passed');

        // Failures spread wider than the window never accumulate to a lock.
        for (let i = 0; i < 4; i += 1) await post('/mfa/verify', { mfaChallengeToken: token, code: await wrongCode(secret) });
        await new Promise((r) => setTimeout(r, 1200));
        assert.equal((await post('/mfa/verify', { mfaChallengeToken: token, code: await wrongCode(secret) })).status, 400, 'a new window starts the count over');
    } finally {
        Object.assign(lockout, saved);
    }
});

test('confirmMfa (enrolment) and disableMfa codes are counted too — and share the counter with login verification', async () => {
    // Enrolment.
    const enrolEmail = uniqueEmail('lock-confirm');
    const { accessToken } = await registerVerifyLogin(enrolEmail);
    const auth = { Authorization: `Bearer ${accessToken}` };
    const { secret } = await (await fetch(`${server.baseUrl}/me/mfa/setup`, { method: 'POST', headers: auth })).json();
    for (let i = 0; i < 4; i += 1) assert.equal((await post('/me/mfa/confirm', { code: await wrongCode(secret) }, auth)).status, 400);
    assert.equal((await post('/me/mfa/confirm', { code: await wrongCode(secret) }, auth)).status, 429);
    const confirmRight = await post('/me/mfa/confirm', { code: await generateTotp({ secret }) }, auth);
    assert.equal(confirmRight.status, 429);
    assert.equal((await confirmRight.json()).recoveryCodes, undefined);

    // Disable — 3 wrong codes there + 2 at login verification = locked everywhere.
    const user = await userWithMfa('lock-disable');
    const userAuth = { Authorization: `Bearer ${user.accessToken}` };
    const disable = (code) => fetch(`${server.baseUrl}/me/mfa`, { method: 'DELETE', headers: { 'Content-Type': 'application/json', 'X-Forwarded-For': nextIp(), ...userAuth }, body: JSON.stringify({ password, code }) });
    for (let i = 0; i < 3; i += 1) assert.equal((await disable(await wrongCode(user.secret))).status, 400);
    const token = await challenge(user.email);
    assert.equal((await post('/mfa/verify', { mfaChallengeToken: token, code: await wrongCode(user.secret) })).status, 400);
    assert.equal((await post('/mfa/verify', { mfaChallengeToken: token, code: await wrongCode(user.secret) })).status, 429);
    assert.equal((await disable(await generateTotp({ secret: user.secret }))).status, 429, 'disable refused while locked, even with the right code');
    const stillOn = await app.state.storage.userRepository.findById(user.userId);
    assert.equal(stillOn.mfaEnabled, true);
});

test('the rate limiter fails CLOSED on backend error for login, MFA, password reset and magic-link keys', async () => {
    const saved = app.state.rateLimiter;
    app.state.rateLimiter = {
        increment: async () => { throw new Error('redis down'); },
        check: async () => { throw new Error('redis down'); },
        reset: async () => {},
    };
    try {
        const cases = [
            ['/login', { email: 'x@example.com', password }],
            ['/mfa/verify', { mfaChallengeToken: 'x', code: '123456' }],
            ['/webauthn/mfa/verify', { mfaChallengeToken: 'x', response: { id: 'x', rawId: 'x', type: 'public-key', response: {} } }],
            ['/password/forgot', { email: 'x@example.com' }],
            ['/magic-link/request', { email: 'x@example.com' }],
        ];
        for (const [path, body] of cases) {
            const res = await post(path, body);
            assert.equal(res.status, 503, path);
            assert.equal((await res.json()).error, 'RATE_LIMITER_UNAVAILABLE', path);
        }
        // Refresh keeps its explicit fail-open: the request proceeds to the token check.
        const refresh = await post('/refresh', { refreshToken: 'not-a-real-token' });
        assert.equal(refresh.status, 401);
    } finally {
        app.state.rateLimiter = saved;
    }
});

test('enforceRateLimit: failMode closed rejects on backend error; the default stays open', async () => {
    const state = { rateLimiter: { increment: async () => { throw new Error('boom'); } }, logger: null };
    await assert.rejects(enforceRateLimit(state, 'k', { max: 1, windowSeconds: 1 }, { failMode: 'closed' }), (err) => err.code === 'RATE_LIMITER_UNAVAILABLE' && err.httpStatus === 503);
    await assert.doesNotReject(enforceRateLimit(state, 'k', { max: 1, windowSeconds: 1 }));
});

test('an attempt-counter backend error fails closed — no tokens issued', async () => {
    const { email, secret } = await userWithMfa('lock-backend');
    const saved = app.state.attemptCounters;
    app.state.attemptCounters = { get: async () => { throw new Error('db down'); }, recordFailure: async () => { throw new Error('db down'); }, reset: async () => {} };
    try {
        const res = await post('/mfa/verify', { mfaChallengeToken: await challenge(email), code: await generateTotp({ secret }) });
        assert.equal(res.status, 500);
        assert.equal((await res.json()).accessToken, undefined);
    } finally {
        app.state.attemptCounters = saved;
    }
});

test('MemoryAttemptCounterRepository (fallback for adapters without one): window, lock, and an active lock surviving its window', async () => {
    let now = 1_000_000;
    const repo = new MemoryAttemptCounterRepository({ now: () => now });
    const opts = { max: 3, windowSeconds: 10, lockSeconds: 60 };
    assert.equal((await repo.recordFailure('k', opts)).count, 1);
    assert.equal((await repo.recordFailure('k', opts)).lockedUntil, null);
    const third = await repo.recordFailure('k', opts);
    assert.equal(third.count, 3);
    assert.equal(third.lockedUntil.getTime(), now + 60_000);

    now += 20_000; // window over, lock still active
    const during = await repo.recordFailure('k', opts);
    assert.equal(during.count, 4, 'an active lock is never reset by its window running out');
    assert.equal(during.lockedUntil.getTime(), third.lockedUntil.getTime());

    now += 60_000; // lock over
    const afterLock = await repo.recordFailure('k', opts);
    assert.equal(afterLock.count, 1);
    assert.equal(afterLock.lockedUntil, null);

    await repo.reset('k');
    assert.equal(await repo.get('k'), null);
});
