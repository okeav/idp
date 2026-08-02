import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import { buildKeyRegistry } from '../src/signing/key-registry.js';
import { issueAccessToken, verifyAccessToken } from '../src/signing/token.service.js';

function generateKeyPair() {
    return crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
}

function buildState(keysConfig) {
    return {
        config: { issuer: 'https://idp.test.local', ttls: { accessToken: 3600 } },
        signingKeys: buildKeyRegistry(keysConfig),
    };
}

test('a token signed by a since-REVOKED key no longer verifies, even though its kid is still in the registry', async () => {
    const { privateKey, publicKey } = generateKeyPair();

    const activeState = buildState({ k1: { privateKey, publicKey, status: 'ACTIVE' } });
    const { token } = await issueAccessToken(activeState, { sub: 'user-1' });

    // Sanity check: verifies fine while the key is still ACTIVE.
    const payload = await verifyAccessToken(activeState, token);
    assert.equal(payload.sub, 'user-1');

    // The key is revoked (e.g. after a suspected compromise) but its kid is left
    // in the registry (as a real deployment would, to keep the audit trail).
    const revokedState = buildState({ k1: { privateKey, publicKey, status: 'REVOKED' } });

    await assert.rejects(
        () => verifyAccessToken(revokedState, token),
        (err) => {
            assert.equal(err.code, 'INVALID_TOKEN');
            assert.equal(err.httpStatus, 401);
            return true;
        },
        'a token signed by a REVOKED key must not verify just because its kid still resolves',
    );
});

test('a token signed by a RETIRED key still verifies (rotation grace period, not revocation)', async () => {
    const { privateKey, publicKey } = generateKeyPair();

    const activeState = buildState({ k1: { privateKey, publicKey, status: 'ACTIVE' } });
    const { token } = await issueAccessToken(activeState, { sub: 'user-2' });

    // The key rotates out to RETIRED (no longer used for new signing) but should
    // still verify tokens issued while it was active — same set /keys/:kid allows.
    const retiredState = buildState({ k1: { privateKey, publicKey, status: 'RETIRED' } });
    const payload = await verifyAccessToken(retiredState, token);
    assert.equal(payload.sub, 'user-2');
});
