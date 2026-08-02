---
title: "Cache Interface"
package: "@okeav/idp-core"
category: "api-reference"
tags: ["cache", "redis", "storage-adapter"]
description: "The CacheAdapter contract, built-in memory/Redis adapters, and the fail-closed revocation-check invariant."
---

# Cache Interface

The cache layer backs revocation checks (logout, refresh rotation), SSO CSRF-state, WebAuthn
challenges, and OIDC discovery caching. It's pluggable behind a small four-method interface.

## `CacheAdapter` contract

```ts
interface CacheAdapter {
  get(key: string): Promise<unknown | null>;
  set(key: string, value: unknown, ttlSeconds?: number): Promise<void>;
  del(key: string): Promise<void>;
  expire(key: string, ttlSeconds: number): Promise<void>;
}
```

`BaseCacheAdapter` (exported from `src/cache/cache-adapter.js`, not on the public package surface)
exists purely for documentation/`instanceof` purposes — adapters don't need to extend it, only to
satisfy the shape above.

`createCacheAdapter(config)` (internal — called by `initIdentityProvider`) wraps whichever raw
adapter is selected in a **key-prefixing decorator** (`config.cache.keyPrefix`, default `'idp:'`)
before storing it in state — every key your own code or this package's internals pass through
`state.cache` is automatically prefixed.

## `config.cache`

```ts
{
  adapter?: 'memory' | 'redis'; // default 'memory'
  keyPrefix?: string;           // default 'idp:'
  redis?: { host: string; port: number; password?: string; db?: number; keepAliveMs?: number };
}
```

## `MemoryCacheAdapter`

```ts
class MemoryCacheAdapter implements CacheAdapter {
  constructor(opts?: { sweepIntervalMs?: number }); // default 60_000
  close(): void; // stops the background sweep timer
}
```

Zero-config default. **Single-process, in-memory only** — state is lost on restart and **not
shared across instances**. Fine for local dev or a genuinely single-instance deployment; **wrong
for anything horizontally scaled**, because two invariants silently break:

1. Revocation checks (logout, refresh rotation) only apply on the instance that handled the
   revoking request — a different instance still accepts the "revoked" token.
2. SSO CSRF-state and WebAuthn challenges aren't shared, so a callback/verify landing on a
   different instance than the one that issued the challenge spuriously fails.

Backed by a `Map`, swept every `sweepIntervalMs` to evict expired entries proactively (in addition
to the lazy expiry check on `get`).

## `RedisCacheAdapter` / `createRedisCacheAdapter(opts)`

```ts
class RedisCacheAdapter implements CacheAdapter {
  constructor(opts: { redis: IORedisClient }); // requires an already-connected client
  get client(): IORedisClient; // exposed so the rate limiter can share this connection
}
function createRedisCacheAdapter(opts: {
  host: string; port: number; password?: string; db?: number; keepAliveMs?: number;
}): Promise<RedisCacheAdapter>
```

Recommended for production/multi-instance deployments. `ioredis` is a **peer dependency** —
dynamically `import()`-ed only when this adapter is actually instantiated, so consumers on the
memory default never need to install it. `createRedisCacheAdapter` connects with
`lazyConnect: true`, `maxRetriesPerRequest: 3`, and a `retryStrategy` capped at 5s between
attempts, then awaits `.connect()` before returning.

Values are JSON-serialized on `set` (raw strings are stored as-is) and JSON-parsed on `get`
(falling back to the raw string if parsing fails).

## Fail-closed revocation checks

**This is a security invariant, not adapter-specific behavior.** The internal `isRevoked(cache,
key)` helper (used by `authContextMiddleware`):

- A cache **miss** (key genuinely absent) legitimately means "not revoked" → returns `false`.
- A cache **error** (adapter threw — connection down, timeout, etc.) means revocation status is
  *unknown* → throws `IdpError({ code: 'CACHE_UNAVAILABLE', httpStatus: 503 })` rather than
  treating the failure as "not revoked." The caller must reject the token.

This is the inverse of [rate limiting](rate-limiter-interface.md)'s fail-open backend behavior —
revocation is a security check, rate limiting is defense-in-depth.

## Writing a custom adapter

Any object satisfying the four-method `CacheAdapter` shape can be passed where the built-in
adapters are used — there's no dedicated `config.cache.factory` extension point (unlike storage);
instead, construct your adapter and either use it directly via the exported classes as a
reference, or fork `createCacheAdapter`'s selection logic in your own bootstrap if you need a
third backend. See [Redis Cache Adapter example](../examples/redis-cache-adapter.md) for a
working `config.cache.adapter = 'redis'` setup.

## Related

- [Rate Limiter Interface](rate-limiter-interface.md) — shares the Redis connection when both
  adapters are set to `'redis'` with no separate `rateLimiting.redis` block.
- [Middleware](middleware.md) — `authContextMiddleware`'s revocation check.
- [WebAuthn](webauthn.md) — challenge storage uses the cache with `config.ttls.webauthnChallenge`.
