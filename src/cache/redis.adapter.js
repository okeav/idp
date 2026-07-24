import { BaseCacheAdapter } from './cache-adapter.js';

/**
 * Recommended for production / multi-instance deployments. `ioredis` is a
 * peerDependency — it is only imported when this adapter is actually
 * instantiated, so consumers who stick with the in-memory default never
 * need to install it.
 */
export class RedisCacheAdapter extends BaseCacheAdapter {
    constructor({ redis } = {}) {
        super();
        if (!redis) throw new Error('RedisCacheAdapter requires a connected ioredis client instance (pass via { redis })');
        this._redis = redis;
    }

    /** The underlying ioredis client — exposed so other subsystems (e.g. the Redis rate limiter) can share this connection instead of opening a second one. */
    get client() {
        return this._redis;
    }

    async get(key) {
        const raw = await this._redis.get(key);
        if (raw === null || raw === undefined) return null;
        try {
            return JSON.parse(raw);
        } catch {
            return raw;
        }
    }

    async set(key, value, ttlSeconds) {
        const payload = typeof value === 'string' ? value : JSON.stringify(value);
        if (ttlSeconds) {
            await this._redis.set(key, payload, 'EX', ttlSeconds);
        } else {
            await this._redis.set(key, payload);
        }
    }

    async del(key) {
        await this._redis.del(key);
    }

    async expire(key, ttlSeconds) {
        await this._redis.expire(key, ttlSeconds);
    }
}

/**
 * Constructs an ioredis client and wraps it. Dynamically imports `ioredis`
 * so it's never required unless this factory is actually called.
 */
export async function createRedisCacheAdapter({ host, port, password, db = 0, keepAliveMs = 10_000 } = {}) {
    let IORedis;
    try {
        ({ default: IORedis } = await import('ioredis'));
    } catch (err) {
        throw new Error(
            'Cache adapter "redis" was configured but the "ioredis" peer dependency is not installed. ' +
            'Run `npm install ioredis` or switch cache.adapter to "memory".'
        );
    }

    const redis = new IORedis({
        host,
        port,
        password,
        db,
        lazyConnect: true,
        maxRetriesPerRequest: 3,
        keepAlive: keepAliveMs,
        retryStrategy: (times) => Math.min(times * 500, 5000),
    });

    await redis.connect();

    return new RedisCacheAdapter({ redis });
}
