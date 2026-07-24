import { MemoryRateLimiter } from './memory.adapter.js';
import { createRedisRateLimiter } from './redis.adapter.js';
import { NoopRateLimiter } from './noop.adapter.js';

export { BaseRateLimiter } from './rate-limiter.js';
export { MemoryRateLimiter } from './memory.adapter.js';
export { RedisRateLimiter, createRedisRateLimiter } from './redis.adapter.js';
export { NoopRateLimiter } from './noop.adapter.js';

/**
 * @param {object} [config]
 * @param {boolean} [config.enabled=true] - set false to disable entirely (e.g. you already rate-limit at a gateway/CDN)
 * @param {'memory'|'redis'} [config.adapter='memory']
 * @param {string} [config.keyPrefix='ratelimit:']
 * @param {object} [config.redis] - { host, port, password, db } — only read if adapter === 'redis' and no shared client is available
 * @param {import('ioredis').Redis} [sharedRedisClient] - reused automatically when config.cache.adapter === 'redis' and rateLimiting.adapter is also 'redis' with no separate connection details of its own
 * @returns {Promise<import('./rate-limiter.js').RateLimiter>}
 */
export async function createRateLimiter(config = {}, sharedRedisClient = null) {
    if (config.enabled === false) return prefixed(new NoopRateLimiter(), '');

    const adapter = config.adapter || 'memory';
    const prefix = config.keyPrefix ?? 'ratelimit:';

    let raw;
    if (adapter === 'redis') {
        // Explicit connection details in config.rateLimiting.redis win; otherwise
        // reuse the cache adapter's Redis client if one is already connected.
        raw = config.redis?.host
            ? await createRedisRateLimiter(config.redis)
            : await createRedisRateLimiter({ redis: sharedRedisClient });
    } else if (adapter === 'memory') {
        raw = new MemoryRateLimiter();
    } else {
        throw new Error(`Unknown rate limiter adapter "${adapter}" — expected "memory" or "redis"`);
    }

    return prefixed(raw, prefix);
}

function prefixed(limiter, prefix) {
    const k = (key) => `${prefix}${key}`;
    return {
        check: (key) => limiter.check(k(key)),
        increment: (key, opts) => limiter.increment(k(key), opts),
        reset: (key) => limiter.reset(k(key)),
    };
}
