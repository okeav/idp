import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { generate as generateTotp } from 'otplib';
import { buildTestApp, withTemporaryApp, uniqueEmail, TEST_SECURITY, freshTotp, waitForHookCall } from './helpers/build-test-app.js';
import { json } from './helpers/serve.js';

// Account-takeover paths found in the 0.3.0 audit:
//  - pre-registration: an attacker registers the victim's email with a password
//    they know; the account later becomes active (via the victim's own
//    verification, or a magic link) with the attacker's password still on it;
//  - the 6-digit email-verification code could be guessed without limit;
//  - magic-link login skipped MFA.

const attackerPassword = 'Att4cker!Passw0rd';
const victimPassword = 'V1ctim!Passw0rd';

let app;

before(async () => {
    app = await buildTestApp();
});

after(async () => {
    await app.stop();
});

const post = (path, body, headers) => fetch(`${app.baseUrl}${path}`, json(body, headers));
const lastCodeFor = (email, a = app) => a.hookCalls.onVerificationEmailRequested.filter((c) => c.email === email).at(-1);

async function magicLinkLogin(email) {
    assert.equal((await post('/magic-link/request', { email })).status, 200);
    const token = app.hookCalls.onMagicLinkRequested.filter((c) => c.email === email).at(-1).magicLinkToken;
    const res = await post('/magic-link/verify', { token });
    return { status: res.status, body: await res.json() };
}

async function enableMfa(accessToken) {
    const auth = { Authorization: `Bearer ${accessToken}` };
    const { secret } = await (await fetch(`${app.baseUrl}/me/mfa/setup`, { method: 'POST', headers: auth })).json();
    const confirm = await post('/me/mfa/confirm', { code: await generateTotp({ secret }) }, auth);
    assert.equal(confirm.status, 200);
    return secret;
}

test('pre-registration (attacker first): the victim activates their own password; the attacker\'s code is useless to them', async () => {
    const email = uniqueEmail('prereg');
    assert.equal((await post('/register', { email, password: attackerPassword })).status, 201);
    const attackersCode = lastCodeFor(email).verificationCode;

    // The victim registers "their" account — previously silently accepted while keeping the attacker's password.
    assert.equal((await post('/register', { email, password: victimPassword })).status, 201);
    const victimsCode = lastCodeFor(email).verificationCode;
    assert.notEqual(victimsCode, attackersCode, 'a fresh code is sent for the new registration');

    // Two registrations competed for the address: a code alone no longer verifies, and the code of
    // the attacker's registration (also in the victim's inbox) does not go with the victim's password.
    const bare = await post('/register/verify-email', { email, code: victimsCode });
    assert.equal(bare.status, 400);
    assert.equal((await bare.json()).error, 'REGISTRATION_PASSWORD_REQUIRED');
    assert.equal((await post('/register/verify-email', { email, code: attackersCode, password: victimPassword })).status, 400);
    assert.equal((await post('/register/verify-email', { email, code: victimsCode, password: victimPassword })).status, 200, 'refused attempts did not burn the code');

    assert.equal((await post('/login', { email, password: attackerPassword })).status, 401, 'the attacker\'s password must not survive');
    assert.equal((await post('/login', { email, password: victimPassword })).status, 200);
});

test('pre-registration (victim first): re-registering right after the victim does not hand the attacker the account', async () => {
    const email = uniqueEmail('prereg-vf');
    // The attacker plants a registration; while it is pending, login with its password says nothing.
    await post('/register', { email, password: attackerPassword });
    const plantedRight = await post('/login', { email, password: attackerPassword });
    const plantedWrong = await post('/login', { email, password: 'Wr0ng!Passw0rd' });
    assert.equal(plantedRight.status, 401);
    assert.deepEqual(await plantedRight.json(), await plantedWrong.json(), 'no "pending" oracle for the right password');

    await post('/register', { email, password: victimPassword });
    const victimsCode = lastCodeFor(email).verificationCode;
    // The attacker re-registers immediately: the newest email in the victim's inbox is the attacker's.
    await post('/register', { email, password: attackerPassword });
    const newestCode = lastCodeFor(email).verificationCode;

    // The victim, entering the newest code with their password, does not activate the attacker's.
    assert.equal((await post('/register/verify-email', { email, code: newestCode, password: victimPassword })).status, 400);
    // Their own registration's code still works.
    assert.equal((await post('/register/verify-email', { email, code: victimsCode, password: victimPassword })).status, 200);
    assert.equal((await post('/login', { email, password: attackerPassword })).status, 401);
    assert.equal((await post('/login', { email, password: victimPassword })).status, 200);
});

test('a single registration still verifies with the code alone', async () => {
    const email = uniqueEmail('single-reg');
    await post('/register', { email, password: victimPassword });
    assert.equal((await post('/register/verify-email', { email, code: lastCodeFor(email).verificationCode })).status, 200);
    assert.equal((await post('/login', { email, password: victimPassword })).status, 200);
});

test('the stored (HMAC) form of a verification code is not accepted as the code', async () => {
    const email = uniqueEmail('hmac-code');
    await post('/register', { email, password: victimPassword });
    const user = await app.state.storage.userRepository.findByEmail(email);
    const row = await app.state.storage.connection.model('IdpVerificationToken').findOne({ user: user.id, kind: 'email_verification' }).lean();
    assert.ok(row.verificationCode && !/^\d{6}$/.test(row.verificationCode), 'stored hashed');
    assert.equal((await post('/register/verify-email', { email, code: row.verificationCode })).status, 400);
});

test('pre-registration: activating a pending account by magic link discards the password set before ownership was proven', async () => {
    const email = uniqueEmail('prereg-ml');
    await post('/register', { email, password: attackerPassword });

    const { status, body } = await magicLinkLogin(email);
    assert.equal(status, 200, JSON.stringify(body));
    assert.ok(body.accessToken);

    const attacker = await post('/login', { email, password: attackerPassword });
    assert.equal(attacker.status, 401, 'the pre-registered password is gone');
    assert.equal((await attacker.json()).error, 'INVALID_CREDENTIALS');

    // The outstanding email-verification code from the attacker's registration is gone too.
    const leftover = await post('/register/verify-email', { email, code: lastCodeFor(email).verificationCode });
    assert.equal(leftover.status, 400);
});

/** The answer to /register and /register/resend-verification: always a status and a (random) ticket, whatever the address. */
function assertTicketAnswer(body) {
    assert.deepEqual(Object.keys(body).sort(), ['status', 'verificationTicket']);
    assert.equal(body.status, 'ok');
    assert.match(body.verificationTicket, /^[0-9a-f]{64}$/);
}

test('re-registering an ACTIVE account changes nothing and gives the same answer', async () => {
    const email = uniqueEmail('active-rereg');
    await post('/register', { email, password: victimPassword });
    await post('/register/verify-email', { email, code: lastCodeFor(email).verificationCode });
    const callsBefore = app.hookCalls.onVerificationEmailRequested.length;

    const res = await post('/register', { email, password: attackerPassword });
    assert.equal(res.status, 201);
    assertTicketAnswer(await res.json());
    assert.equal(app.hookCalls.onVerificationEmailRequested.length, callsBefore, 'no email sent');
    assert.equal((await post('/login', { email, password: attackerPassword })).status, 401);
    assert.equal((await post('/login', { email, password: victimPassword })).status, 200);
});

test('password login on a passwordless account answers 401 INVALID_CREDENTIALS (was a bcrypt 500)', async () => {
    const email = uniqueEmail('passwordless');
    assert.equal((await magicLinkLogin(email)).status, 200);
    const res = await post('/login', { email, password: 'Anything!123' });
    assert.equal(res.status, 401);
    assert.equal((await res.json()).error, 'INVALID_CREDENTIALS');
});

test('magic-link login stops at the MFA challenge when the account has MFA', async () => {
    const email = uniqueEmail('ml-mfa');
    const first = await magicLinkLogin(email);
    const secret = await enableMfa(first.body.accessToken);

    const { status, body } = await magicLinkLogin(email);
    assert.equal(status, 200);
    assert.equal(body.mfaRequired, true);
    assert.ok(body.mfaChallengeToken);
    assert.equal(body.accessToken, undefined, 'no session before the second factor');
    assert.equal(body.refreshToken, undefined);

    const verify = await post('/mfa/verify', { mfaChallengeToken: body.mfaChallengeToken, code: await freshTotp(app.state, first.body.userId, secret) });
    assert.equal(verify.status, 200);
    assert.ok((await verify.json()).accessToken);
});

test('verify-email answers the same for an unknown address, a verified one, and a wrong code', async () => {
    const verified = uniqueEmail('verified');
    await post('/register', { email: verified, password: victimPassword });
    await post('/register/verify-email', { email: verified, code: lastCodeFor(verified).verificationCode });
    const pending = uniqueEmail('pending');
    await post('/register', { email: pending, password: victimPassword });

    const bodies = [];
    for (const email of [uniqueEmail('nobody'), verified, pending]) {
        const res = await post('/register/verify-email', { email, code: '000000' });
        assert.equal(res.status, 400, email);
        bodies.push(await res.json());
    }
    assert.deepEqual(bodies[0], bodies[1]);
    assert.deepEqual(bodies[1], bodies[2]);

    // resend-verification likewise says nothing about an already-verified address.
    const resend = await post('/register/resend-verification', { email: verified });
    assert.equal(resend.status, 200);
    assertTicketAnswer(await resend.json());
});

test('email-verification codes are stored hashed, not in plain text', async () => {
    const email = uniqueEmail('hashed-code');
    await post('/register', { email, password: victimPassword });
    const { verificationCode } = lastCodeFor(email);
    const user = await app.state.storage.userRepository.findByEmail(email);
    const rows = await app.state.storage.connection.model('IdpVerificationToken').find({ user: user.id, kind: 'email_verification' }).lean();
    assert.equal(rows.length, 1);
    assert.notEqual(rows[0].verificationCode, verificationCode);
    assert.match(rows[0].verificationCode, /^[0-9a-f]{64}$/);
});

test('verify-email brute force: without a ticket the address budget locks, even for the right code — the registrant ticket is unaffected', async () => {
    await withTemporaryApp({ config: { security: { ...TEST_SECURITY, verificationCodeLockout: { maxFailedAttempts: 3, windowSeconds: 60, lockSeconds: 60 } } } }, async (temp) => {
        const p = (path, body) => fetch(`${temp.baseUrl}${path}`, json(body));
        const email = uniqueEmail('bruteforce');
        const { verificationTicket } = await (await p('/register', { email, password: victimPassword })).json();
        const { verificationCode } = lastCodeFor(email, temp);
        const wrong = verificationCode === '123456' ? '654321' : '123456';

        for (let i = 0; i < 2; i += 1) assert.equal((await p('/register/verify-email', { email, code: wrong })).status, 400);
        const exhausting = await p('/register/verify-email', { email, code: wrong });
        assert.equal(exhausting.status, 429, 'the wrong attempt that uses up the budget already answers locked');
        assert.equal((await exhausting.json()).error, 'VERIFICATION_LOCKED');
        const locked = await p('/register/verify-email', { email, code: verificationCode });
        assert.equal(locked.status, 429, 'the right code is refused once the budget is spent');
        assert.equal((await locked.json()).error, 'VERIFICATION_LOCKED');
        assert.ok(temp.hookCalls.onAuditLog.some((e) => e.action === 'EMAIL_VERIFICATION_LOCKED' && e.withTicket === false));

        // The browser that registered carries its ticket: its own budget, untouched by the stranger's guesses.
        assert.equal((await p('/register/verify-email', { email, code: verificationCode, ticket: verificationTicket })).status, 200);
    });
});

test('verify-email brute force: a concurrent burst gets no more guesses than the budget', async () => {
    await withTemporaryApp({ config: { security: { ...TEST_SECURITY, verificationCodeLockout: { maxFailedAttempts: 5, windowSeconds: 60, lockSeconds: 60 } } } }, async (temp) => {
        const email = uniqueEmail('burst');
        await fetch(`${temp.baseUrl}/register`, json({ email, password: victimPassword }));
        const { verificationCode } = lastCodeFor(email, temp);

        // 40 simultaneous wrong guesses: with check-then-count, all 40 would be checked.
        const guesses = Array.from({ length: 40 }, (_, i) => String((Number(verificationCode) + 1 + i) % 1000000).padStart(6, '0'));
        const statuses = await Promise.all(guesses.map(async (code) => (await fetch(`${temp.baseUrl}/register/verify-email`, json({ email, code }))).status));
        // Exactly 5 guesses are checked: 4 answer "wrong", the 5th uses up the budget (locked, one
        // audit event); the other 35 are refused before their code is looked at.
        assert.equal(statuses.filter((s) => s === 400).length, 4, `exactly the budget is checked (got ${statuses.join(',')})`);
        assert.equal(statuses.filter((s) => s === 429).length, 36);
        const user = await temp.state.storage.userRepository.findByEmail(email);
        assert.equal(temp.hookCalls.onAuditLog.filter((e) => e.action === 'EMAIL_VERIFICATION_LOCKED' && e.userId === String(user.id)).length, 1);
        assert.equal((await fetch(`${temp.baseUrl}/register/verify-email`, json({ email, code: verificationCode }))).status, 429);
    });
});

test('a successful verification resets the attempt budget (no stale lock carried over)', async () => {
    await withTemporaryApp({ config: { security: { ...TEST_SECURITY, verificationCodeLockout: { maxFailedAttempts: 3, windowSeconds: 60, lockSeconds: 60 } } } }, async (temp) => {
        const p = (path, body) => fetch(`${temp.baseUrl}${path}`, json(body));
        const email = uniqueEmail('reset-budget');
        await p('/register', { email, password: victimPassword });
        const { verificationCode } = lastCodeFor(email, temp);
        const wrong = verificationCode === '123456' ? '654321' : '123456';
        assert.equal((await p('/register/verify-email', { email, code: wrong })).status, 400);
        assert.equal((await p('/register/verify-email', { email, code: wrong })).status, 400);
        assert.equal((await p('/register/verify-email', { email, code: verificationCode })).status, 200);
        const user = await temp.state.storage.userRepository.findByEmail(email);
        assert.equal(await temp.state.attemptCounters.get(`email-verification:${user.id}`), null);
    });
});

test('registration and resend are rate limited per address (no inbox flooding) and per IP', async () => {
    await withTemporaryApp({ config: { rateLimiting: { enabled: true, verificationEmailByEmail: { max: 2, windowSeconds: 60 }, register: { max: 5, windowSeconds: 60 } } } }, async (temp) => {
        const p = (path, body) => fetch(`${temp.baseUrl}${path}`, json(body));
        const email = uniqueEmail('flood');
        assert.equal((await p('/register', { email, password: victimPassword })).status, 201);
        assert.equal((await p('/register/resend-verification', { email })).status, 200);
        const third = await p('/register/resend-verification', { email });
        assert.equal(third.status, 429);
        assert.equal((await third.json()).error, 'RATE_LIMIT_EXCEEDED');

        // Per IP: 5 register/resend requests in the window (2 used above), across any addresses.
        assert.equal((await p('/register', { email: uniqueEmail('ip1'), password: victimPassword })).status, 201);
        assert.equal((await p('/register', { email: uniqueEmail('ip2'), password: victimPassword })).status, 201);
        assert.equal((await p('/register', { email: uniqueEmail('ip3'), password: victimPassword })).status, 429);
    });
});
