import crypto from 'crypto';

/**
 * Blind index for email lookups. IdentityUser stores the plaintext email
 * (display, OIDC claims, outbound mail) but every lookup goes through an
 * HMAC-SHA-256 of the normalized email keyed by a server-side pepper — so a
 * leaked database without the pepper can't be brute-forced for common
 * addresses, and only this IDP instance can compute the lookup hash.
 *
 * Rotating the pepper invalidates every existing hash — treat it as a
 * non-rotating, well-backed-up secret.
 */
export function normalizeEmail(email) {
    return String(email ?? '').trim().toLowerCase();
}

export function makeHashEmail(pepper) {
    if (!pepper) throw new Error('config.security.emailHashPepper is required');
    return function hashEmail(email) {
        if (!email) return null;
        return crypto.createHmac('sha256', pepper).update(normalizeEmail(email)).digest('hex');
    };
}
