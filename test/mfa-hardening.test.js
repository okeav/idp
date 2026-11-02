import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { generate as generateTotp, verify as verifyTotp } from 'otplib';
import { buildTestApp, uniqueEmail, freshTotp } from './helpers/build-test-app.js';
import { json } from './helpers/serve.js';
import { withAttemptBudget } from '../src/security/attempt-budget.js';
import { MemoryAttemptCounterRepository } from '../src/mfa/memory-attempt-counter.js';

// MFA issues found in the 0.3.0 audit:
//  - the per-account lockout was check-then-count, so a concurrent burst got
//    every one of its guesses checked;
//  - a TOTP code stayed valid for its whole ±30s window however often it was
//    used, and a challenge token for its whole 5 minutes;
//  - a recovery code was matched, then marked used with a separate write, so
//    two concurrent requests could both spend it;
//  - recovery codes could be regenerated with the password alone.

const password = 'Str0ng!Passw0rd';
let app;

before(async () => {
    app = await buildTestApp();
});

after(async () => {
    await app.stop();
});

const post = (path, body, headers) => fetch(`${app.baseUrl}${path}`, json(body, headers));
const del = (path, body, headers) => fetch(`${app.baseUrl}${path}`, { ...json(body, headers), method: 'DELETE' });

async function userWithMfa(prefix) {
    const email = uniqueEmail(prefix);
    await post('/register', { email, password });
    const code = app.hookCalls.onVerificationEmailRequested.filter((c) => c.email === email).at(-1).verificationCode;
    await post('/register/verify-email', { email, code });
    const { accessToken, userId } = await (await post('/login', { email, password })).json();
    const auth = { Authorization: `Bearer ${accessToken}` };
    const { secret } = await (await fetch(`${app.baseUrl}/me/mfa/setup`, { method: 'POST', headers: auth })).json();
    const confirm = await post('/me/mfa/confirm', { code: await generateTotp({ secret }) }, auth);
    assert.equal(confirm.status, 200);
    const { recoveryCodes } = await confirm.json();
    return { email, userId, secret, recoveryCodes, auth };
}

async function challenge(email) {
    const { mfaChallengeToken } = await (await post('/login', { email, password })).json();
    assert.ok(mfaChallengeToken);
    return mfaChallengeToken;
}

async function wrongCode(secret) {
    for (let n = 0; ; n += 1) {
        const candidate = String((Number(await generateTotp({ secret })) + 123457 + n) % 1000000).padStart(6, '0');
        if (!(await verifyTotp({ token: candidate, secret, epochTolerance: 30 })).valid) return candidate;
    }
}

test('a TOTP code is accepted once: replaying it (with a new challenge) is refused', async () => {
    const { email, userId, secret } = await userWithMfa('totp-replay');
    const code = await freshTotp(app.state, userId, secret);

    assert.equal((await post('/mfa/verify', { mfaChallengeToken: await challenge(email), code })).status, 200);
    const replay = await post('/mfa/verify', { mfaChallengeToken: await challenge(email), code });
    assert.equal(replay.status, 400);
    assert.equal((await replay.json()).error, 'INVALID_MFA_CODE');
});

test('the code that confirmed enrolment cannot then complete a login', async () => {
    const email = uniqueEmail('enrol-replay');
    await post('/register', { email, password });
    await post('/register/verify-email', { email, code: app.hookCalls.onVerificationEmailRequested.filter((c) => c.email === email).at(-1).verificationCode });
    const { accessToken } = await (await post('/login', { email, password })).json();
    const auth = { Authorization: `Bearer ${accessToken}` };
    const { secret } = await (await fetch(`${app.baseUrl}/me/mfa/setup`, { method: 'POST', headers: auth })).json();
    const code = await generateTotp({ secret });
    assert.equal((await post('/me/mfa/confirm', { code }, auth)).status, 200);

    assert.equal((await post('/mfa/verify', { mfaChallengeToken: await challenge(email), code })).status, 400);
});

test('two concurrent logins with the same TOTP code: exactly one succeeds', async () => {
    const { email, userId, secret } = await userWithMfa('totp-race');
    const code = await freshTotp(app.state, userId, secret);
    const [t1, t2, t3] = [await challenge(email), await challenge(email), await challenge(email)];
    const statuses = await Promise.all([t1, t2, t3].map(async (t) => (await post('/mfa/verify', { mfaChallengeToken: t, code })).status));
    assert.deepEqual(statuses.sort(), [200, 400, 400]);
});

test('a challenge token completes one login only', async () => {
    const { email, userId, secret } = await userWithMfa('challenge-once');
    const token = await challenge(email);
    assert.equal((await post('/mfa/verify', { mfaChallengeToken: token, code: await freshTotp(app.state, userId, secret) })).status, 200);

    const again = await post('/mfa/verify', { mfaChallengeToken: token, code: await freshTotp(app.state, userId, secret) });
    assert.equal(again.status, 401);
    assert.equal((await again.json()).error, 'INVALID_MFA_CHALLENGE_TOKEN');
});

test('a challenge token issued before a password change is void', async () => {
    const { email, userId, secret, auth } = await userWithMfa('challenge-pwchange');
    const token = await challenge(email); // earned with the old password

    await new Promise((r) => setTimeout(r, 1100)); // passwordChangedAt lands in a later second than the token's iat
    const change = await post('/password/change', { currentPassword: password, newPassword: 'N3w!Passw0rd' }, auth);
    assert.equal(change.status, 200, await change.text());

    const res = await post('/mfa/verify', { mfaChallengeToken: token, code: await freshTotp(app.state, userId, secret) });
    assert.equal(res.status, 401);
    assert.equal((await res.json()).error, 'INVALID_MFA_CHALLENGE_TOKEN');
});

test('two concurrent logins with the same recovery code: exactly one succeeds, and the code is spent once', async () => {
    const { email, userId, recoveryCodes } = await userWithMfa('recovery-race');
    const tokens = [await challenge(email), await challenge(email), await challenge(email)];
    const statuses = await Promise.all(tokens.map(async (t) => (await post('/mfa/verify', { mfaChallengeToken: t, code: recoveryCodes[0] })).status));
    assert.deepEqual(statuses.sort(), [200, 400, 400]);

    const user = await app.state.storage.userRepository.findById(userId, { select: '+mfaRecoveryCodes' });
    assert.equal(user.mfaRecoveryCodes.filter((rc) => rc.usedAt).length, 1);
});

test('recovery codes are accepted regardless of case and surrounding whitespace', async () => {
    const { email, recoveryCodes } = await userWithMfa('recovery-case');
    const res = await post('/mfa/verify', { mfaChallengeToken: await challenge(email), code: `  ${recoveryCodes[2].toLowerCase()} ` });
    assert.equal(res.status, 200, await res.text());
});

test('MFA lockout: a concurrent burst of wrong codes gets exactly the budget checked', async () => {
    const { email, userId, secret } = await userWithMfa('burst');
    const token = await challenge(email);
    const codes = await Promise.all(Array.from({ length: 30 }, () => wrongCode(secret)));
    const statuses = await Promise.all(codes.map(async (code) => (await post('/mfa/verify', { mfaChallengeToken: token, code })).status));

    // Budget 5: four answered "wrong", the fifth used it up (locked); 25 refused unchecked.
    assert.equal(statuses.filter((s) => s === 400).length, 4, statuses.join(','));
    assert.equal(statuses.filter((s) => s === 429).length, 26);
    assert.equal(app.hookCalls.onAuditLog.filter((e) => e.action === 'MFA_LOCKED' && e.userId === String(userId)).length, 1);
    assert.equal((await post('/mfa/verify', { mfaChallengeToken: token, code: await freshTotp(app.state, userId, secret) })).status, 429);
});

test('wrong MFA codes do not count toward the password lockout', async () => {
    const { email, userId, secret } = await userWithMfa('no-conflation');
    const token = await challenge(email);
    for (let i = 0; i < 3; i += 1) await post('/mfa/verify', { mfaChallengeToken: token, code: await wrongCode(secret) });
    const user = await app.state.storage.userRepository.findById(userId);
    assert.equal(user.failedLoginAttempts, 0);
});

test('regenerating recovery codes needs a TOTP code as well as the password', async () => {
    const { userId, secret, auth } = await userWithMfa('regen');
    const noCode = await post('/me/mfa/recovery-codes', { password }, auth);
    assert.equal(noCode.status, 400, 'code is required');

    const wrong = await post('/me/mfa/recovery-codes', { password, code: await wrongCode(secret) }, auth);
    assert.equal(wrong.status, 400);
    assert.equal((await wrong.json()).error, 'INVALID_MFA_CODE');

    const badPassword = await post('/me/mfa/recovery-codes', { password: 'Wr0ng!Passw0rd', code: await freshTotp(app.state, userId, secret) }, auth);
    assert.equal((await badPassword.json()).error, 'CURRENT_PASSWORD_INCORRECT');

    const ok = await post('/me/mfa/recovery-codes', { password, code: await freshTotp(app.state, userId, secret) }, auth);
    assert.equal(ok.status, 200);
    assert.equal(ok.headers.get('cache-control'), 'no-store');
    assert.equal((await ok.json()).recoveryCodes.length, app.state.config.mfa.recoveryCodeCount);
});

test('disabling MFA: the password is required when the account has one, and not when it has none', async () => {
    const withPassword = await userWithMfa('disable-pw');
    const missing = await del('/me/mfa', { code: await freshTotp(app.state, withPassword.userId, withPassword.secret) }, withPassword.auth);
    assert.equal(missing.status, 400);
    assert.equal((await missing.json()).error, 'CURRENT_PASSWORD_INCORRECT');

    // A magic-link (passwordless) account re-authenticates with the code alone.
    const email = uniqueEmail('disable-nopw');
    await post('/magic-link/request', { email });
    const token = app.hookCalls.onMagicLinkRequested.filter((c) => c.email === email).at(-1).magicLinkToken;
    const { accessToken, userId } = await (await post('/magic-link/verify', { token })).json();
    const auth = { Authorization: `Bearer ${accessToken}` };
    const { secret } = await (await fetch(`${app.baseUrl}/me/mfa/setup`, { method: 'POST', headers: auth })).json();
    assert.equal((await post('/me/mfa/confirm', { code: await generateTotp({ secret }) }, auth)).status, 200);

    const disabled = await del('/me/mfa', { code: await freshTotp(app.state, userId, secret) }, auth);
    const disabledBody = await disabled.json();
    assert.equal(disabled.status, 200, JSON.stringify(disabledBody));
    assert.equal(disabledBody.mfaEnabled, false);
});

test('withAttemptBudget counts the attempt before verify runs, and resets on success', async () => {
    const state = { attemptCounters: new MemoryAttemptCounterRepository() };
    const limits = { maxFailedAttempts: 2, windowSeconds: 60, lockSeconds: 60 };
    const lockedError = () => Object.assign(new Error('locked'), { code: 'LOCKED' });

    let seenCount;
    await withAttemptBudget(state, 'k', limits, { lockedError }, async () => {
        seenCount = (await state.attemptCounters.get('k')).count;
    });
    assert.equal(seenCount, 1, 'counted before verify ran');
    assert.equal(await state.attemptCounters.get('k'), null, 'reset after success');

    const fail = () => withAttemptBudget(state, 'k', limits, { lockedError }, async () => { throw new Error('wrong'); });
    await assert.rejects(fail(), /wrong/);
    await assert.rejects(fail(), (err) => err.code === 'LOCKED', 'the failure that uses up the budget answers locked');
    let ran = false;
    await assert.rejects(withAttemptBudget(state, 'k', limits, { lockedError }, async () => { ran = true; }), (err) => err.code === 'LOCKED');
    assert.equal(ran, false, 'a locked key never reaches verify');

    // A non-guess error that uses up the budget keeps its own error.
    const s2 = { attemptCounters: new MemoryAttemptCounterRepository() };
    await assert.rejects(withAttemptBudget(s2, 'k', { ...limits, maxFailedAttempts: 1 }, { lockedError, isFailure: () => false }, async () => { throw new Error('expired'); }), /expired/);
});
