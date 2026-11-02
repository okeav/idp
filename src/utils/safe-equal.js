import crypto from 'crypto';

/**
 * Constant-time comparison of two secrets of any length: both are hashed first, so neither the
 * content nor the length of the expected secret leaks through timing.
 */
export function safeEqualSecret(presented, expected) {
    if (typeof presented !== 'string' || typeof expected !== 'string' || expected.length === 0) return false;
    const a = crypto.createHash('sha256').update(presented).digest();
    const b = crypto.createHash('sha256').update(expected).digest();
    return crypto.timingSafeEqual(a, b);
}
