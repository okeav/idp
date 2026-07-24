import { IdpError } from '../errors/idp-error.js';

/**
 * Throws `RATE_LIMIT_EXCEEDED` (429) when the given key has exceeded its
 * window. Rate limiting is defense-in-depth, not the sole protection —
 * account lockout (`security.maxFailedLoginAttempts`) is a separate,
 * independent mechanism that still applies regardless of this check. So
 * unlike the cache revocation check, a rate-limiter *backend* error (Redis
 * down, timeout) fails OPEN here: it's logged and the request proceeds,
 * rather than turning an infra hiccup into a full login outage.
 */
export async function enforceRateLimit(state, key, { max, windowSeconds }) {
    let result;
    try {
        result = await state.rateLimiter.increment(key, { max, windowSeconds });
    } catch (err) {
        state.logger?.warn?.({ err, key }, 'Rate limiter backend errored — allowing the request through (fail-open)');
        return;
    }
    if (!result.allowed) {
        throw new IdpError({ code: 'RATE_LIMIT_EXCEEDED', httpStatus: 429, message: 'Too many requests — please try again later.' });
    }
}
