import { IdpError } from '../errors/idp-error.js';

/**
 * Throws `RATE_LIMIT_EXCEEDED` (429) when the given key has exceeded its
 * window.
 *
 * `failMode` decides what a rate-limiter *backend* error (Redis down,
 * timeout) does:
 *  - `'closed'` — reject with `RATE_LIMITER_UNAVAILABLE` (503). Used for
 *    every key guarding a credential check (login, MFA, password reset,
 *    magic link): an attacker who can knock the limiter over must not get
 *    unlimited guesses as a result.
 *  - `'open'` (the default, kept only where a call site chooses it) — log
 *    and let the request through, for limits whose job is load-shedding
 *    rather than brute-force protection (e.g. token refresh).
 *
 * @param {{ max: number, windowSeconds: number }} rule
 * @param {{ failMode?: 'open' | 'closed' }} [opts]
 */
export async function enforceRateLimit(state, key, { max, windowSeconds }, { failMode = 'open' } = {}) {
    let result;
    try {
        result = await state.rateLimiter.increment(key, { max, windowSeconds });
    } catch (err) {
        if (failMode === 'closed') {
            state.logger?.error?.({ err, key }, 'Rate limiter backend errored — rejecting the request (fail-closed)');
            throw new IdpError({ code: 'RATE_LIMITER_UNAVAILABLE', httpStatus: 503, message: 'Service temporarily unavailable — please try again shortly.', cause: err });
        }
        state.logger?.warn?.({ err, key }, 'Rate limiter backend errored — allowing the request through (fail-open)');
        return;
    }
    if (!result.allowed) {
        throw new IdpError({ code: 'RATE_LIMIT_EXCEEDED', httpStatus: 429, message: 'Too many requests — please try again later.' });
    }
}
