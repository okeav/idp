import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import { generate as generateTotp, generateSecret } from 'otplib';
import { buildTestApp, uniqueEmail, TEST_MFA_KEY } from './helpers/build-test-app.js';
import { json } from './helpers/serve.js';
import { initIdentityProvider, migrateMfaSecrets, AesGcmSecretCipher } from '../src/index.js';
import { getState, setState } from '../src/config/state.js';

// Issue: mfaSecret / mfaTempSecret were stored in plain text.

let app;

before(async () => {
    app = await buildTestApp();
});

after(async () => {
    await app.stop();
});

const key = () => crypto.randomBytes(32).toString('base64');

async function registerVerifyLogin(email, password) {
    await fetch(`${app.baseUrl}/register`, json({ email, password }));
    const code = app.hookCalls.onVerificationEmailRequested.find((c) => c.email === email).verificationCode;
    await fetch(`${app.baseUrl}/register/verify-email`, json({ email, code }));
    return (await fetch(`${app.baseUrl}/login`, json({ email, password }))).json();
}

async function enrol(accessToken) {
    const auth = { Authorization: `Bearer ${accessToken}` };
    const { secret } = await (await fetch(`${app.baseUrl}/me/mfa/setup`, { method: 'POST', headers: auth })).json();
    const confirm = await fetch(`${app.baseUrl}/me/mfa/confirm`, json({ code: await generateTotp({ secret }) }, auth));
    assert.equal(confirm.status, 200, await confirm.text());
    return secret;
}

async function mfaLogin(email, password, secret) {
    const { mfaChallengeToken } = await (await fetch(`${app.baseUrl}/login`, json({ email, password }))).json();
    assert.ok(mfaChallengeToken);
    return fetch(`${app.baseUrl}/mfa/verify`, json({ mfaChallengeToken, code: await generateTotp({ secret }) }));
}

const readSecrets = (userId) => app.state.storage.userRepository.findById(userId, { select: '+mfaSecret +mfaTempSecret' });

/** Writes raw values straight to storage, bypassing the cipher — what a pre-0.3.0 install left behind. */
const writeRaw = (userId, patch) => app.state.storage.userRepository.updateById(userId, patch);

async function withConfig(patch, fn) {
    const mfa = app.state.config.mfa;
    const saved = { ...mfa };
    Object.assign(mfa, patch);
    try {
        return await fn();
    } finally {
        for (const k of Object.keys(mfa)) delete mfa[k];
        Object.assign(mfa, saved);
    }
}

async function withCipher(cipher, fn) {
    const saved = app.state.mfaCipher;
    app.state.mfaCipher = cipher;
    try {
        return await fn();
    } finally {
        app.state.mfaCipher = saved;
    }
}

test('the stored mfaTempSecret and mfaSecret are never the secret itself; enrolment + login round-trip', async () => {
    const email = uniqueEmail('mfa-enc');
    const password = 'Str0ng!Passw0rd';
    const { accessToken, userId } = await registerVerifyLogin(email, password);

    const { secret } = await (await fetch(`${app.baseUrl}/me/mfa/setup`, { method: 'POST', headers: { Authorization: `Bearer ${accessToken}` } })).json();
    let stored = await readSecrets(userId);
    assert.ok(stored.mfaTempSecret.startsWith('v1:'), stored.mfaTempSecret);
    assert.ok(!stored.mfaTempSecret.includes(secret));

    const confirm = await fetch(`${app.baseUrl}/me/mfa/confirm`, json({ code: await generateTotp({ secret }) }, { Authorization: `Bearer ${accessToken}` }));
    assert.equal(confirm.status, 200);
    stored = await readSecrets(userId);
    assert.ok(stored.mfaSecret.startsWith('v1:'));
    assert.ok(!stored.mfaSecret.includes(secret));
    assert.notEqual(stored.mfaSecret, secret);
    assert.equal(stored.mfaTempSecret, null);

    const verify = await mfaLogin(email, password, secret);
    const body = await verify.json();
    assert.equal(verify.status, 200, JSON.stringify(body));
    assert.ok(body.accessToken);
});

test('AesGcmSecretCipher: tampering with any part, the wrong key, or another user\'s context fails closed', () => {
    const k1 = key();
    const cipher = new AesGcmSecretCipher({ currentKey: k1 });
    const secret = generateSecret();
    const sealed = cipher.encrypt(secret, { context: 'user-a' });
    assert.equal(cipher.decrypt(sealed, { context: 'user-a' }), secret);

    const parts = sealed.split(':');
    const flip = (b64) => {
        const buf = Buffer.from(b64, 'base64url');
        buf[0] ^= 0x01;
        return buf.toString('base64url');
    };
    for (const idx of [2, 3, 4]) {
        const tampered = parts.map((p, i) => (i === idx ? flip(p) : p)).join(':');
        assert.throws(() => cipher.decrypt(tampered, { context: 'user-a' }), undefined, `tampered part ${idx} must not decrypt`);
    }
    assert.throws(() => cipher.decrypt(sealed, { context: 'user-b' }), undefined, 'a secret copied onto another user must not decrypt');

    // Same key id, different key material.
    const imposter = new AesGcmSecretCipher({ currentKey: { id: parts[1], key: key() } });
    assert.throws(() => imposter.decrypt(sealed, { context: 'user-a' }));
    // Unknown key id.
    assert.throws(() => new AesGcmSecretCipher({ currentKey: key() }).decrypt(sealed, { context: 'user-a' }), /No MFA encryption key/);
    // Garbage / wrong format.
    assert.throws(() => cipher.decrypt('v1:abc', { context: 'user-a' }));
    assert.throws(() => cipher.decrypt(secret, { context: 'user-a' }));

    assert.throws(() => new AesGcmSecretCipher({ currentKey: Buffer.alloc(16).toString('base64') }), /32 bytes/);
});

test('a tampered stored secret, or the wrong key, refuses MFA login (no tokens issued)', async () => {
    const email = uniqueEmail('mfa-tamper');
    const password = 'Str0ng!Passw0rd';
    const { accessToken, userId } = await registerVerifyLogin(email, password);
    const secret = await enrol(accessToken);

    // Wrong key: the app restarted with a different key and no previous key configured.
    await withCipher(new AesGcmSecretCipher({ currentKey: key() }), async () => {
        const res = await mfaLogin(email, password, secret);
        assert.equal(res.status, 500);
        const body = await res.json();
        assert.equal(body.error, 'MFA_SECRET_UNREADABLE');
        assert.equal(body.accessToken, undefined);
    });

    // Tampered ciphertext in the database.
    const { mfaSecret } = await readSecrets(userId);
    const parts = mfaSecret.split(':');
    const ct = Buffer.from(parts[3], 'base64url');
    ct[ct.length - 1] ^= 0xff;
    parts[3] = ct.toString('base64url');
    await writeRaw(userId, { mfaSecret: parts.join(':') });
    const res = await mfaLogin(email, password, secret);
    assert.equal(res.status, 500);
    assert.equal((await res.json()).error, 'MFA_SECRET_UNREADABLE');
});

test('key rotation: old ciphertext still decrypts under previousEncryptionKeys and is re-sealed under the new key on verify', async () => {
    const email = uniqueEmail('mfa-rotate');
    const password = 'Str0ng!Passw0rd';
    const { accessToken, userId } = await registerVerifyLogin(email, password);
    const secret = await enrol(accessToken);
    const before = (await readSecrets(userId)).mfaSecret;
    const oldKeyId = before.split(':')[1];

    const rotated = new AesGcmSecretCipher({ currentKey: { id: 'k2', key: key() }, previousKeys: [TEST_MFA_KEY] });
    assert.equal(rotated.needsRotation(before), true);
    await withCipher(rotated, async () => {
        const res = await mfaLogin(email, password, secret);
        assert.equal(res.status, 200, await res.text());
        const after = (await readSecrets(userId)).mfaSecret;
        assert.equal(after.split(':')[1], 'k2', 'lazily re-encrypted under the current key');
        assert.notEqual(after.split(':')[1], oldKeyId);
        // And it still works after the re-seal.
        assert.equal((await mfaLogin(email, password, secret)).status, 200);
    });
});

test('lazy migration: a legacy plain-text secret still verifies and is encrypted on the next successful verify', async () => {
    const email = uniqueEmail('mfa-legacy');
    const password = 'Str0ng!Passw0rd';
    const { userId } = await registerVerifyLogin(email, password);
    const secret = generateSecret();
    await writeRaw(userId, { mfaEnabled: true, mfaSecret: secret, mfaRecoveryCodes: [] });

    // A wrong code doesn't rewrite anything.
    const { mfaChallengeToken } = await (await fetch(`${app.baseUrl}/login`, json({ email, password }))).json();
    const wrong = String((Number(await generateTotp({ secret })) + 500000) % 1000000).padStart(6, '0');
    assert.equal((await fetch(`${app.baseUrl}/mfa/verify`, json({ mfaChallengeToken, code: wrong }))).status, 400);
    assert.equal((await readSecrets(userId)).mfaSecret, secret);

    const res = await mfaLogin(email, password, secret);
    assert.equal(res.status, 200, await res.text());
    const stored = (await readSecrets(userId)).mfaSecret;
    assert.ok(stored.startsWith('v1:'), 'migrated to ciphertext');
    assert.notEqual(stored, secret);
    assert.equal((await mfaLogin(email, password, secret)).status, 200, 'still verifies once encrypted');
});

test('confirm encrypts a legacy plain-text mfaTempSecret left over from before the upgrade', async () => {
    const email = uniqueEmail('mfa-legacy-temp');
    const password = 'Str0ng!Passw0rd';
    const { accessToken, userId } = await registerVerifyLogin(email, password);
    const secret = generateSecret();
    await writeRaw(userId, { mfaTempSecret: secret });

    const res = await fetch(`${app.baseUrl}/me/mfa/confirm`, json({ code: await generateTotp({ secret }) }, { Authorization: `Bearer ${accessToken}` }));
    assert.equal(res.status, 200, await res.text());
    const stored = await readSecrets(userId);
    assert.ok(stored.mfaSecret.startsWith('v1:'));
    assert.equal(stored.mfaTempSecret, null);
});

test('migrateMfaSecrets() encrypts every plain-text secret in one pass; dry run changes nothing; second run is a no-op', async () => {
    const password = 'Str0ng!Passw0rd';
    const users = [];
    for (let i = 0; i < 3; i += 1) {
        const email = uniqueEmail(`mfa-migrate-${i}`);
        const { userId } = await registerVerifyLogin(email, password);
        const secret = generateSecret();
        await writeRaw(userId, { mfaEnabled: true, mfaSecret: secret, ...(i === 0 ? { mfaTempSecret: generateSecret() } : {}) });
        users.push({ email, userId, secret });
    }

    const dry = await migrateMfaSecrets({ dryRun: true, batchSize: 2 });
    assert.ok(dry.encrypted >= 4, JSON.stringify(dry));
    assert.equal((await readSecrets(users[0].userId)).mfaSecret, users[0].secret, 'dry run must not write');

    const result = await migrateMfaSecrets({ batchSize: 2 });
    // Users left under a key this cipher doesn't hold (the rotation test's
    // "k2") are reported per user without aborting the run.
    const ours = new Set(users.map((u) => String(u.userId)));
    assert.deepEqual(result.failed.filter((f) => ours.has(f.userId)), []);
    assert.ok(result.failed.every((f) => /No MFA encryption key/.test(f.error)), JSON.stringify(result.failed));
    for (const u of users) {
        const stored = await readSecrets(u.userId);
        assert.ok(stored.mfaSecret.startsWith('v1:'), `${u.email} migrated`);
        assert.equal((await mfaLogin(u.email, password, u.secret)).status, 200);
    }
    assert.ok((await readSecrets(users[0].userId)).mfaTempSecret.startsWith('v1:'), 'mfaTempSecret migrated too');

    const again = await migrateMfaSecrets();
    assert.equal(again.encrypted, 0);
    assert.equal(again.reencrypted, 0);
});

test('migrateMfaSecrets() also re-encrypts secrets written under a previous key', async () => {
    const email = uniqueEmail('mfa-migrate-rotate');
    const password = 'Str0ng!Passw0rd';
    const { accessToken, userId } = await registerVerifyLogin(email, password);
    const secret = await enrol(accessToken);

    await withCipher(new AesGcmSecretCipher({ currentKey: { id: 'k3', key: key() }, previousKeys: [TEST_MFA_KEY] }), async () => {
        const result = await migrateMfaSecrets();
        assert.ok(result.reencrypted >= 1);
        assert.equal((await readSecrets(userId)).mfaSecret.split(':')[1], 'k3');
        assert.equal((await mfaLogin(email, password, secret)).status, 200);
    });
});

test('mfa.requireEncrypted refuses a plain-text secret instead of using it', async () => {
    const email = uniqueEmail('mfa-require');
    const password = 'Str0ng!Passw0rd';
    const { userId } = await registerVerifyLogin(email, password);
    const secret = generateSecret();
    await writeRaw(userId, { mfaEnabled: true, mfaSecret: secret, mfaRecoveryCodes: [] });

    await withConfig({ requireEncrypted: true }, async () => {
        const res = await mfaLogin(email, password, secret);
        assert.equal(res.status, 500);
        const body = await res.json();
        assert.equal(body.error, 'MFA_SECRET_NOT_ENCRYPTED');
        assert.equal(body.accessToken, undefined);
        assert.equal((await readSecrets(userId)).mfaSecret, secret, 'not silently migrated either');
    });
});

// ── Startup validation ──────────────────────────────────────────────────────

function fakeStorage() {
    return {
        close: async () => {}, userRepository: {}, sessionRepository: {}, authorizationCodeRepository: {}, consentRepository: {},
        oauthClientRepository: {}, verificationTokenRepository: {}, serviceKeyRepository: {}, credentialRepository: {},
    };
}

async function tryInit(mfa) {
    const previous = (() => { try { return getState(); } catch { return null; } })();
    const warnings = [];
    const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048, publicKeyEncoding: { type: 'spki', format: 'pem' }, privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    try {
        await initIdentityProvider({
            issuer: 'https://startup.test.local',
            storage: { factory: async () => fakeStorage() },
            signingKeys: { keys: { k: { privateKey, publicKey, status: 'ACTIVE' } } },
            security: { emailHashPepper: 'p', tokenHashSecret: 's' },
            logger: { info() {}, warn: (_o, msg) => warnings.push(msg), error() {}, debug() {} },
            ...(mfa === undefined ? {} : { mfa }),
        });
        return { ok: true, warnings };
    } catch (err) {
        return { ok: false, error: err, warnings };
    } finally {
        if (previous) setState(previous);
    }
}

test('startup fails when MFA is enabled with no key or cipher; allowPlaintext opts out loudly', async () => {
    const none = await tryInit(undefined);
    assert.equal(none.ok, false);
    assert.match(none.error.message, /encryptionKey/);

    const dev = await tryInit({ allowPlaintext: true });
    assert.equal(dev.ok, true);
    assert.ok(dev.warnings.some((w) => /UNENCRYPTED/.test(w)), 'allowPlaintext must log a loud warning');

    assert.equal((await tryInit({ enabled: false })).ok, true, 'a deployment that doesn\'t use MFA needs no key');
    assert.equal((await tryInit({ encryptionKey: key() })).ok, true);
    assert.equal((await tryInit({ secretCipher: { encrypt: (p) => `kms:${p}`, decrypt: (c) => c.slice(4) } })).ok, true);

    const short = await tryInit({ encryptionKey: Buffer.alloc(31).toString('base64') });
    assert.equal(short.ok, false);
    assert.match(short.error.message, /32 bytes/);

    const contradictory = await tryInit({ allowPlaintext: true, requireEncrypted: true });
    assert.equal(contradictory.ok, false);
    assert.match(contradictory.error.message, /requireEncrypted/);

    const badCipher = await tryInit({ secretCipher: { encrypt: () => 'x' } });
    assert.equal(badCipher.ok, false);
});
