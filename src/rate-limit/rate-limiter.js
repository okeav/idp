/**
 * @typedef {Object} RateLimitResult
 * @property {boolean} allowed
 * @property {number} remaining
 * @property {number} resetAt - epoch ms when the window resets
 *
 * @typedef {Object} RateLimiter
 * @property {(key: string) => Promise<RateLimitResult>} check - read-only peek, does not consume an attempt
 * @property {(key: string, opts: {max: number, windowSeconds: number}) => Promise<RateLimitResult>} increment - atomically consumes one attempt against a fixed window, creating it if absent
 * @property {(key: string) => Promise<void>} reset - clears a key (e.g. on successful login)
 */

/** Base class purely for documentation / instanceof checks — adapters aren't required to extend it. */
export class BaseRateLimiter {
    async check(_key) { throw new Error('RateLimiter.check() not implemented'); }
    async increment(_key, _opts) { throw new Error('RateLimiter.increment() not implemented'); }
    async reset(_key) { throw new Error('RateLimiter.reset() not implemented'); }
}
