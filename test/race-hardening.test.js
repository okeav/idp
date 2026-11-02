import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { buildTestApp, withTemporaryApp, uniqueEmail, waitForHookCall, TEST_SECURITY } from './helpers/build-test-app.js';
import { json } from './helpers/serve.js';
import { gate } from './helpers/gate.js';

// Findings of the second (races / protocol / data) review. Interleavings are forced with gate().

const attackerPassword = 'Att4cker!Passw0rd';
const victimPassword = 'V1ctim!Passw0rd';
let app;

before(async () => {
    app = await buildTestApp();
});

after(async () => {
    await app.stop();
});

const post = (path, body, headers, base = app.baseUrl) => fetch(`${base}${path}`, json(body, headers));
const lastCode = (email, a = app) => a.hookCalls.onVerificationEmailRequested.filter((c) => c.email === email).at(-1);
const users = () => app.state.storage.userRepository;
const rows = (filter) => app.state.storage.connection.model('IdpVerificationToken').find(filter).lean();

async function magicLinkToken(email) {
    await post('/magic-link/request', { email });
    return app.hookCalls.onMagicLinkRequested.filter((c) => c.email === email).at(-1).magicLinkToken;
}

// ── Pre-account takeover ─────────────────────────────────────────────────────

test('a password reset on a never-verified account activates it, so the pre-registration code cannot later activate the attacker\'s password', async () => {
    const email = uniqueEmail('reset-pending');
    await post('/register', { email, password: attackerPassword }); // the attacker's pre-registration
    const { verificationCode, verificationToken } = lastCode(email);

    // The victim can't sign in, so resets the password from their inbox.
    await post('/password/forgot', { email });
    const { resetToken } = await waitForHookCall(app, 'onPasswordResetRequested', (c) => c.email === email);
    assert.equal((await post('/password/reset', { email, token: resetToken, newPassword: victimPassword })).status, 200);
    assert.equal((await post('/login', { email, password: victimPassword })).status, 200, 'the reset activated the account');

    // The registration email's code and link no longer do anything.
    assert.equal((await post('/register/verify-email', { email, code: verificationCode })).status, 400);
    assert.equal((await post('/register/verify-email', { email, token: verificationToken })).status, 400);
    assert.equal((await post('/login', { email, password: attackerPassword })).status, 401);
    assert.equal((await post('/login', { email, password: victimPassword })).status, 200);
});

test('a re-registration that read the account as pending cannot overwrite it once a magic link activated it', async () => {
    const email = uniqueEmail('race-ml');
    await post('/register', { email, password: attackerPassword });
    const token = await magicLinkToken(email);

    // The attacker's second registration reads PENDING and is held there...
    const g = gate(users(), 'findByEmail', { pred: (e) => e === email });
    const register = post('/register', { email, password: attackerPassword });
    await g.reached;
    g.restore();
    // ...while the owner signs in by magic link (activating the account, passwordless).
    assert.equal((await post('/magic-link/verify', { token })).status, 200);
    g.release();
    assert.equal((await register).status, 201);

    assert.equal((await post('/login', { email, password: attackerPassword })).status, 401, 'no attacker password on the live account');
});

test('a re-registration that read the account as pending cannot overwrite it once the owner verified', async () => {
    const email = uniqueEmail('race-verify');
    await post('/register', { email, password: victimPassword });
    const victimsCode = lastCode(email).verificationCode;

    const g = gate(users(), 'findByEmail', { pred: (e) => e === email });
    const register = post('/register', { email, password: attackerPassword });
    await g.reached;
    g.restore();
    assert.equal((await post('/register/verify-email', { email, code: victimsCode })).status, 200);
    g.release();
    await register;

    assert.equal((await post('/login', { email, password: attackerPassword })).status, 401);
    assert.equal((await post('/login', { email, password: victimPassword })).status, 200);
});

// ── Verification-code budget ─────────────────────────────────────────────────

test('wrong codes from a stranger kill the codes, not the owner\'s link; the lock looks the same for every address', async () => {
    await withTemporaryApp({ config: { security: { ...TEST_SECURITY, verificationCodeLockout: { maxFailedAttempts: 3, windowSeconds: 60, lockSeconds: 60 } } } }, async (temp) => {
        const p = (path, body) => post(path, body, {}, temp.baseUrl);
        const burn = async (email) => {
            const answers = [];
            for (let i = 0; i < 4; i += 1) {
                const res = await p('/register/verify-email', { email, code: String(100000 + i) });
                answers.push({ status: res.status, body: await res.json() });
            }
            return answers;
        };

        const pending = uniqueEmail('burn-pending');
        await p('/register', { email: pending, password: victimPassword });
        const { verificationCode, verificationToken } = lastCode(pending, temp);

        const pendingAnswers = await burn(pending);
        const unknownAnswers = await burn(uniqueEmail('burn-unknown'));
        assert.deepEqual(pendingAnswers, unknownAnswers, 'a pending registration is indistinguishable from an unknown address');
        assert.equal(pendingAnswers.at(-1).status, 429);

        assert.equal((await p('/register/verify-email', { email: pending, code: verificationCode })).status, 429, 'codes are locked');
        assert.equal((await p('/register/verify-email', { email: pending, token: verificationToken })).status, 200, 'the emailed link still works');
    });
});

test('a right code with a wrong password (contested registration) is never consumed, so nothing has to be put back', async () => {
    const email = uniqueEmail('no-putback');
    await post('/register', { email, password: victimPassword });
    await post('/register', { email, password: attackerPassword }); // contested
    const { verificationCode } = lastCode(email);
    const before = await rows({ kind: 'email_verification' });
    assert.equal((await post('/register/verify-email', { email, code: verificationCode, password: victimPassword })).status, 400);
    const afterRows = await rows({ kind: 'email_verification' });
    assert.deepEqual(afterRows.map((r) => String(r._id)).sort(), before.map((r) => String(r._id)).sort(), 'same rows — none consumed and re-created');
});

// ── One live link per user ───────────────────────────────────────────────────

test('concurrent forgot-password and magic-link requests leave exactly one live link each', async () => {
    const email = uniqueEmail('one-link');
    await post('/register', { email, password: victimPassword });
    assert.equal((await post('/register/verify-email', { email, code: lastCode(email).verificationCode })).status, 200);
    const user = await users().findByEmail(email);

    await Promise.all(Array.from({ length: 6 }, () => post('/password/forgot', { email })));
    await waitForHookCall(app, 'onPasswordResetRequested', (c) => c.email === email, { count: 6 });
    await Promise.all(Array.from({ length: 6 }, () => post('/magic-link/request', { email })));

    assert.equal((await rows({ kind: 'password_reset', user: user.id, usedAt: null })).length, 1);
    assert.equal((await rows({ kind: 'magic_link', user: user.id })).length, 1);
});
