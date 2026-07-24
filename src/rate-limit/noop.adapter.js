import { BaseRateLimiter } from './rate-limiter.js';

/** Used when `config.rateLimiting.enabled === false` — every check passes, no storage touched. */
export class NoopRateLimiter extends BaseRateLimiter {
    async check() {
        return { allowed: true, remaining: Infinity, resetAt: 0 };
    }

    async increment() {
        return { allowed: true, remaining: Infinity, resetAt: 0 };
    }

    async reset() {}
}
