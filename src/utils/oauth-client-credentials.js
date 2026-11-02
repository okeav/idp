import crypto from 'crypto';
import bcrypt from 'bcrypt';

/**
 * Client secrets are 256-bit random values, so a slow password hash adds nothing — there is no
 * dictionary to search — while bcrypt's ~250 ms per check let anyone with a (public) client_id tie
 * up the libuv thread pool (and with it every login) from a handful of connections. New secrets are
 * stored as `hmac-sha256:<hex>` under the client-secret key derived from `security.tokenHashSecret`
 * (see tokenHashKeys). Hashes made under a previous secret, and bcrypt hashes from before 0.4.0
 * (`$2…`), still verify, and are re-stored under the current key on their next successful use.
 */
const HMAC_PREFIX = 'hmac-sha256:';

export function generateClientId() {
    return crypto.randomBytes(16).toString('hex');
}

export function generateClientSecret() {
    return crypto.randomBytes(32).toString('hex');
}

export function hashClientSecret(clientSecret, hmacKey) {
    if (!hmacKey) throw new Error('hashClientSecret: hmacKey (the derived client-secret key) is required');
    return HMAC_PREFIX + crypto.createHmac('sha256', hmacKey).update(String(clientSecret)).digest('hex');
}

/** True when the stored hash should be replaced by the current format after a successful verify. */
export const isLegacyClientSecretHash = (hash) => typeof hash === 'string' && hash.startsWith('$2');

/**
 * Checks `clientSecret` against the stored `hash`. `hmacKeys`: the current key first, then previous
 * ones. Resolves `{ valid, upgrade }` — `upgrade`: it verified, but not under the current key (a
 * previous key, or bcrypt), so the caller should re-store it.
 */
export async function verifyClientSecret(clientSecret, hash, hmacKeys) {
    const keys = Array.isArray(hmacKeys) ? hmacKeys : [hmacKeys];
    if (typeof clientSecret !== 'string' || typeof hash !== 'string') return { valid: false, upgrade: false };
    if (hash.startsWith(HMAC_PREFIX)) {
        const expected = Buffer.from(hash);
        for (const [i, key] of keys.entries()) {
            const actual = Buffer.from(hashClientSecret(clientSecret, key));
            if (expected.length === actual.length && crypto.timingSafeEqual(expected, actual)) return { valid: true, upgrade: i > 0 };
        }
        return { valid: false, upgrade: false };
    }
    if (isLegacyClientSecretHash(hash)) {
        const valid = await bcrypt.compare(clientSecret, hash);
        return { valid, upgrade: valid };
    }
    return { valid: false, upgrade: false };
}
