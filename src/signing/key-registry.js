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
    }
    return registry;
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
