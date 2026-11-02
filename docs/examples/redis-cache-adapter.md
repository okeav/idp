---
title: "Swap in the Redis Cache Adapter"
package: "@okeav/idp-core"
category: "example"
tags: ["redis", "caching", "mongodb"]
description: "Move from the single-process memory cache adapter to Redis for a horizontally-scaled deployment."
---

# Swap in the Redis Cache Adapter

The default `memory` cache adapter is single-process — revocation checks, SSO CSRF-state, and
WebAuthn challenges aren't shared across instances. Any deployment running more than one process
or pod **must** switch to Redis. See [Cache Interface](../api/cache-interface.md) for the full
`CacheAdapter` contract and why the memory adapter breaks under horizontal scaling.

## Prerequisites

- A running Redis instance (the package repo's `docker-compose.yml` includes one).
- `npm install ioredis` — `ioredis` is a peer dependency, only required if you use this adapter.

## Config change

```js
import { initIdentityProvider } from '@okeav/idp-core';

await initIdentityProvider({
  issuer: 'https://idp.example.com',
  mongo: { uri: process.env.MONGO_URI },
  signingKeys: { keys: { /* ... */ } },
  security: {
    emailHashPepper: process.env.IDP_EMAIL_HASH_PEPPER, // random, ≥ 32 characters
    tokenHashSecret: process.env.IDP_TOKEN_HASH_SECRET, // random, ≥ 32 characters
  },
  mfa: { encryptionKey: process.env.IDP_MFA_ENCRYPTION_KEY },

  cache: {
    adapter: 'redis',
    keyPrefix: 'idp:', // default — every cache key gets this prefix
    redis: {
      host: process.env.REDIS_HOST || '127.0.0.1',
      port: Number(process.env.REDIS_PORT) || 6379,
      username: process.env.REDIS_USERNAME || undefined, // Redis 6 ACL user, if any
      password: process.env.REDIS_PASSWORD || undefined,
      db: 0,
      tls: process.env.REDIS_TLS === 'true', // true (or ioredis TLS options) for managed Redis / anything off the local network
      keepAliveMs: 10_000, // default
    },
  },
});
```

That's the entire change — every handler that reads `state.cache` internally (revocation checks,
SSO state, WebAuthn challenges, OAuth2 consent challenges, OIDC discovery caching) picks up the
Redis-backed adapter automatically; no other config or route wiring changes. With
`configFromEnv()`, the same settings come from `IDP_CACHE_ADAPTER=redis`, `IDP_REDIS_HOST`,
`IDP_REDIS_PORT`, `IDP_REDIS_USERNAME`, `IDP_REDIS_PASSWORD` and `IDP_REDIS_TLS`.

The package repo's `docker-compose.yml` Redis has no authentication and is bound to `127.0.0.1` —
fine for local development only. Anything reachable from elsewhere needs a password (or ACL user)
and TLS.

## Sharing the connection with the rate limiter

If you *also* set `config.rateLimiting.adapter = 'redis'` and don't specify a separate
`config.rateLimiting.redis` block, the rate limiter automatically reuses this same `ioredis`
connection instead of opening a second one:

```js
await initIdentityProvider({
  // ...
  cache: { adapter: 'redis', redis: { host: '127.0.0.1', port: 6379 } },
  rateLimiting: { adapter: 'redis' }, // no `redis:` block — shares the cache adapter's connection
});
```

See [Redis Rate Limiter Adapter](redis-rate-limiter-adapter.md) if you want a **separate** Redis
instance/database for rate-limit counters instead.

## Using the adapter directly (advanced)

`RedisCacheAdapter`/`createRedisCacheAdapter` are exported if you want to construct one yourself
(e.g. to reuse an existing `ioredis` client your app already manages elsewhere) rather than
letting `initIdentityProvider()` build one from `config.cache.redis`:

```js
import Redis from 'ioredis';
import { RedisCacheAdapter } from '@okeav/idp-core';

const existingClient = new Redis({ host: '127.0.0.1', port: 6379 });
const adapter = new RedisCacheAdapter({ redis: existingClient });
// adapter satisfies the CacheAdapter contract directly — useful for testing
// your own code against the same adapter shape idp-core uses internally.
```

If you write your own adapter instead (another backend, or a wrapper around your own Redis
client), it must implement all five methods — including `take(key)`, an **atomic** get-and-delete
added in 0.4.0. The built-in one runs `GET` + `DEL` in a single `MULTI`/`EXEC`:

```js
async take(key) {
  const [[err, raw]] = await this.redis.multi().get(key).del(key).exec();
  if (err) throw err;
  if (raw === null) return null;
  try { return JSON.parse(raw); } catch { return raw; } // set() stores plain strings as-is
}
```

A `get` followed by a separate `del` is not enough: two concurrent requests could both read the
value, and `take()` is what keeps SSO state, WebAuthn challenges and OAuth2 consent challenges
single-use.

## Related

- [Cache Interface](../api/cache-interface.md) — full contract, and the fail-closed revocation
  invariant that applies regardless of which adapter is configured.
- [Redis Rate Limiter Adapter example](redis-rate-limiter-adapter.md)
