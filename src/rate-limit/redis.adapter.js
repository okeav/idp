import { BaseRateLimiter } from './rate-limiter.js';

// Atomic incr-and-maybe-set-expiry, so a concurrent burst of requests can
// never race past the check the way a separate INCR + EXPIRE pair could.
// The expiry is set whenever the key has none (TTL -1), not only on the first
// increment: if that EXPIRE ever failed after INCR committed, the key would
// otherwise never expire and its owner would stay limited forever.
const INCREMENT_SCRIPT = `
local count = redis.call('INCR', KEYS[1])
if redis.call('TTL', KEYS[1]) == -1 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
local ttl = redis.call('TTL', KEYS[1])
return { count, ttl }
`;

export class RedisRateLimiter extends BaseRateLimiter {
    /** @param {{ redis: import('ioredis').Redis }} opts - a connected ioredis client, shared or dedicated */
    constructor({ redis } = {}) {
        super();
        if (!redis) throw new Error('RedisRateLimiter requires a connected ioredis client instance (pass via { redis })');
        this._redis = redis;
    }

    async check(key) {
        const [raw, ttl] = await Promise.all([this._redis.get(key), this._redis.ttl(key)]);
        const count = raw ? Number(raw) : 0;
        return { allowed: true, remaining: Infinity, resetAt: ttl > 0 ? Date.now() + ttl * 1000 : 0, count };
    }

    async increment(key, { max, windowSeconds }) {
        const [count, ttl] = await this._redis.eval(INCREMENT_SCRIPT, 1, key, Math.max(1, Math.ceil(windowSeconds)));
        const resetAt = Date.now() + Math.max(ttl, 0) * 1000;
        return { allowed: count <= max, remaining: Math.max(0, max - count), resetAt };
    }

    async reset(key) {
        await this._redis.del(key);
    }
}

/**
 * @param {{ redis?: import('ioredis').Redis, host?: string, port?: number, password?: string, db?: number }} opts
 *   Pass an existing connected client via `redis` to share the cache
 *   adapter's connection; otherwise a new one is created from host/port/etc,
 *   dynamically importing `ioredis` (peerDependency, only loaded if used).
 */
export async function createRedisRateLimiter(opts = {}) {
    if (opts.redis) return new RedisRateLimiter({ redis: opts.redis });
    if (!opts.host) {
        throw new Error('Rate limiter adapter "redis" needs config.rateLimiting.redis.host, or config.cache.adapter "redis" to share its connection — refusing to connect to an unconfigured localhost');
    }

    let IORedis;
    try {
        ({ default: IORedis } = await import('ioredis'));
    } catch {
        throw new Error(
            'Rate limiter adapter "redis" was configured but the "ioredis" peer dependency is not installed. ' +
            'Run `npm install ioredis`, share an existing client via config.rateLimiting.redis, or switch to "memory".'
        );
    }

    const redis = new IORedis({
        host: opts.host, port: opts.port, username: opts.username, password: opts.password, db: opts.db ?? 0,
        ...(opts.tls ? { tls: opts.tls === true ? {} : opts.tls } : {}),
        lazyConnect: true, maxRetriesPerRequest: 3,
    });
    await redis.connect();
    return new RedisRateLimiter({ redis });
}
