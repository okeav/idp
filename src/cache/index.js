import { MemoryCacheAdapter } from './memory.adapter.js';
import { createRedisCacheAdapter } from './redis.adapter.js';

export { BaseCacheAdapter } from './cache-adapter.js';
export { MemoryCacheAdapter } from './memory.adapter.js';
export { RedisCacheAdapter, createRedisCacheAdapter } from './redis.adapter.js';

/**
 * @param {object} [config]
 * @param {'memory'|'redis'} [config.adapter='memory']
 * @param {string} [config.keyPrefix='idp:']
 * @param {object} [config.redis] - { host, port, password, db, keepAliveMs } — required if adapter === 'redis'
 * @returns {Promise<import('./cache-adapter.js').CacheAdapter>}
 */
export async function createCacheAdapter(config = {}) {
    const adapter = config.adapter || 'memory';
    const prefix = config.keyPrefix ?? 'idp:';

    let raw;
    if (adapter === 'redis') {
        raw = await createRedisCacheAdapter(config.redis || {});
    } else if (adapter === 'memory') {
        raw = new MemoryCacheAdapter();
    } else {
        throw new Error(`Unknown cache adapter "${adapter}" — expected "memory" or "redis"`);
    }

    return prefixed(raw, prefix);
}

function prefixed(adapter, prefix) {
    const k = (key) => `${prefix}${key}`;
    return {
        get: (key) => adapter.get(k(key)),
        set: (key, value, ttlSeconds) => adapter.set(k(key), value, ttlSeconds),
        del: (key) => adapter.del(k(key)),
        expire: (key, ttlSeconds) => adapter.expire(k(key), ttlSeconds),
        close: () => adapter.close?.(),
        // Present only when the underlying adapter is Redis-backed — lets the
        // rate limiter (and anything else that wants Redis) reuse this
        // connection instead of opening a second one.
        redisClient: adapter.client ?? null,
    };
}

/**
 * Fail-closed revocation lookup. A cache MISS (key not present) legitimately
 * means "not revoked" and returns false. A cache ERROR (adapter threw —
 * connection down, timeout, etc.) means we cannot determine revocation
 * status, and this throws rather than returning false — the caller must
 * reject the token instead of silently trusting it. This is a security
 * invariant, independent of which adapter is configured.
 */
export async function isRevoked(cache, key) {
    const { IdpError } = await import('../errors/idp-error.js');
    try {
        const value = await cache.get(key);
        return !!value;
    } catch (cause) {
        throw new IdpError({
            code: 'CACHE_UNAVAILABLE',
            httpStatus: 503,
            message: 'Unable to verify token revocation status',
            cause,
        });
    }
}
