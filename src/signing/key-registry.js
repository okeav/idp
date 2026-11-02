import crypto from 'crypto';
import { KEY_STATUS } from '../config/constants.js';

/**
 * Normalizes a key-material value into a PEM string. Accepts either a raw
 * PEM (detected by the `-----BEGIN` header) or a base64-encoded PEM (the
 * convention the audited Okeav services used, since PEM newlines don't
 * survive some secret-store transports unscathed).
 */
export function resolveKeyMaterial(value) {
    if (!value) return null;
    if (value.includes('-----BEGIN')) return value;
    return Buffer.from(value, 'base64').toString('utf8');
}

/**
 * @param {Record<string, {privateKey?: string, publicKey: string, status: string}>} keysConfig
 * @returns {Record<string, {privateKeyPem: string|null, publicKeyPem: string, status: string}>}
 */
export function buildKeyRegistry(keysConfig = {}) {
    const registry = {};
    for (const [kid, entry] of Object.entries(keysConfig)) {
        registry[kid] = {
            privateKeyPem: entry.privateKey ? resolveKeyMaterial(entry.privateKey) : null,
            publicKeyPem: resolveKeyMaterial(entry.publicKey),
            status: entry.status || KEY_STATUS.ACTIVE,
        };
        assertUsableKey(kid, registry[kid]);
    }
    return registry;
}

/** Startup check: the IdP must be able to sign — at least one ACTIVE (or ROTATING) key with its private key. */
export function assertCanSign(registry) {
    if (!Object.values(registry).some((k) => k.privateKeyPem && [KEY_STATUS.ACTIVE, KEY_STATUS.ROTATING].includes(k.status))) {
        throw new Error('config.signingKeys: at least one ACTIVE (or ROTATING) key needs a privateKey to sign with');
    }
}

const MIN_RSA_BITS = 2048;

/**
 * Fails at startup — not at the first login — on a signing key that can't work or isn't safe: an
 * unparseable PEM, a non-RSA key (tokens are RS256), one under 2048 bits, an unknown status, or a
 * private key that doesn't belong to its public key.
 */
function assertUsableKey(kid, { privateKeyPem, publicKeyPem, status }) {
    const where = `config.signingKeys.keys["${kid}"]`;
    if (!Object.values(KEY_STATUS).includes(status)) throw new Error(`${where}.status must be one of ${Object.values(KEY_STATUS).join(', ')}`);
    let publicKey;
    try {
        publicKey = crypto.createPublicKey(publicKeyPem);
    } catch {
        throw new Error(`${where}.publicKey is not a valid public key (PEM, or base64-encoded PEM)`);
    }
    if (publicKey.asymmetricKeyType !== 'rsa') throw new Error(`${where} must be an RSA key (tokens are signed RS256)`);
    if ((publicKey.asymmetricKeyDetails?.modulusLength ?? 0) < MIN_RSA_BITS) throw new Error(`${where} must be at least ${MIN_RSA_BITS} bits`);
    if (!privateKeyPem) return;
    let privateKey;
    try {
        privateKey = crypto.createPrivateKey(privateKeyPem);
    } catch {
        throw new Error(`${where}.privateKey is not a valid private key (PEM, or base64-encoded PEM)`);
    }
    const probe = Buffer.from(`idp-key-check:${kid}`);
    const signature = crypto.sign('sha256', probe, privateKey);
    if (!crypto.verify('sha256', probe, publicKey, signature)) throw new Error(`${where}: privateKey and publicKey are not a pair`);
}

const PUBLISHABLE_STATUSES = [KEY_STATUS.ACTIVE, KEY_STATUS.ROTATING];

/** Returns [kid, entry] for the current signing key — ACTIVE preferred, ROTATING as fallback. */
export function getActiveSigningKey(registry) {
    const active = Object.entries(registry).find(([, k]) => k.status === KEY_STATUS.ACTIVE);
    if (active) return active;
    const rotating = Object.entries(registry).find(([, k]) => k.status === KEY_STATUS.ROTATING);
    if (rotating) return rotating;
    throw new Error('No ACTIVE or ROTATING signing key configured — set config.signingKeys.keys');
}

/** Every key eligible for verification (ACTIVE + ROTATING), most recently active first. */
export function getVerifiableKeys(registry) {
    return Object.entries(registry).filter(([, k]) => PUBLISHABLE_STATUSES.includes(k.status));
}

/**
 * Looks up a key for verification purposes by `kid`. A REVOKED key never
 * verifies, regardless of `kid` match — this is the one status that must
 * actually invalidate previously-issued tokens, not just stop being
 * published/used for new signing. ACTIVE/ROTATING/RETIRED all still verify,
 * matching the set `/keys/:kid` allows.
 */
export function getPublicKeyByKid(registry, kid) {
    const entry = registry[kid];
    if (!entry || entry.status === KEY_STATUS.REVOKED) return null;
    return entry.publicKeyPem;
}
