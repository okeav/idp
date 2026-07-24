import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import { initIdentityProvider } from '../src/index.js';
import { getState, setState } from '../src/config/state.js';

function generateTestSigningKey() {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    return { privateKey, publicKey };
}

function baseConfig(overrides = {}) {
    const { privateKey, publicKey } = generateTestSigningKey();
    return {
        issuer: 'https://storage-seam.test.local',
        signingKeys: { keys: { 'seam-test-kid': { privateKey, publicKey, status: 'ACTIVE' } } },
        security: {
            emailHashPepper: 'seam-test-pepper',
            tokenHashSecret: 'seam-test-token-secret',
        },
        logger: { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} },
        ...overrides,
    };
}

function fakeStorage() {
    return {
        marker: true,
        close: async () => {},
        userRepository: {},
        sessionRepository: {},
        authorizationCodeRepository: {},
        consentRepository: {},
        oauthClientRepository: {},
        verificationTokenRepository: {},
        serviceKeyRepository: {},
        credentialRepository: {},
    };
}

test('storage seam: an injected config.storage.factory is used instead of the built-in Mongo adapter', async () => {
    let previousState = null;
    try { previousState = getState(); } catch { /* nothing initialized yet in this process */ }

    const storage = fakeStorage();
    let factoryCalledWith = null;

    const state = await initIdentityProvider(baseConfig({
        storage: {
            factory: async (resolvedConfig, deps) => {
                factoryCalledWith = { resolvedConfig, deps };
                return storage;
            },
        },
    }));

    try {
        assert.equal(state.storage, storage, 'initIdentityProvider used the injected factory\'s return value as-is');
        assert.equal(typeof factoryCalledWith.deps.hashEmail, 'function', 'factory received hashEmail');
        assert.equal(typeof factoryCalledWith.deps.normalizeEmail, 'function', 'factory received normalizeEmail');
        assert.equal(factoryCalledWith.resolvedConfig.issuer, 'https://storage-seam.test.local', 'factory received the resolved config');
    } finally {
        if (previousState) setState(previousState);
    }
});

test('storage seam: omitting both config.mongo and config.storage.factory still throws the required-field error', async () => {
    await assert.rejects(
        () => initIdentityProvider(baseConfig()),
        (err) => {
            assert.match(err.message, /config\.mongo .* is required unless config\.storage\.factory is provided/);
            return true;
        }
    );
});
