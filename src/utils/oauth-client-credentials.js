import crypto from 'crypto';
import bcrypt from 'bcrypt';

/**
 * Client secrets are 256-bit random values, so a slow password hash adds nothing — there is no
 * dictionary to search — while bcrypt's ~250 ms per check let anyone with a (public) client_id tie
 * up the libuv thread pool (and with it every login) from a handful of connections. New secrets are
 * stored as `hmac-sha256:<hex>` keyed by `security.tokenHashSecret`. Hashes from before 0.4.0 are
 * bcrypt (`$2…`): still verified, and re-stored as HMAC on their next successful use.
 */
const HMAC_PREFIX = 'hmac-sha256:';

export function generateClientId() {
    return crypto.randomBytes(16).toString('hex');
}

export function generateClientSecret() {
    return crypto.randomBytes(32).toString('hex');
}

export function hashClientSecret(clientSecret, hmacKey) {
    if (!hmacKey) throw new Error('hashClientSecret: hmacKey (security.tokenHashSecret) is required');
    return HMAC_PREFIX + crypto.createHmac('sha256', hmacKey).update(String(clientSecret)).digest('hex');
}

/** True when the stored hash should be replaced by the current format after a successful verify. */
export const isLegacyClientSecretHash = (hash) => typeof hash === 'string' && hash.startsWith('$2');

export async function verifyClientSecret(clientSecret, hash, hmacKey) {
    if (typeof clientSecret !== 'string' || typeof hash !== 'string') return false;
    if (hash.startsWith(HMAC_PREFIX)) {
        const expected = Buffer.from(hash);
        const actual = Buffer.from(hashClientSecret(clientSecret, hmacKey));
        return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
    }
    if (isLegacyClientSecretHash(hash)) return bcrypt.compare(clientSecret, hash);
    return false;
}
