---
title: "Swap in the Redis Rate Limiter Adapter"
package: "@okeav/idp-core"
category: "example"
tags: ["redis", "rate-limiting"]
description: "Move rate-limit counters from the single-process memory adapter to Redis, with or without customizing per-endpoint thresholds."
---

# Swap in the Redis Rate Limiter Adapter

The default `memory` rate-limit adapter counts per-process — each instance in a horizontally
scaled deployment enforces its own independent limit, effectively multiplying the real limit by
instance count. Switch to Redis for a shared, accurate limit. See
[Rate Limiter Interface](../api/rate-limiter-interface.md) for the full contract and the
fail-open backend behavior.

## Prerequisites

- A running Redis instance.
- `npm install ioredis` (peer dependency).

## Config change

```js
await initIdentityProvider({
  // ...
  rateLimiting: {
    enabled: true,       // default
    adapter: 'redis',
    keyPrefix: 'ratelimit:', // default
    redis: { host: '127.0.0.1', port: 6379 }, // omit to share the cache adapter's connection
                                                // instead — see redis-cache-adapter.md
  },
});
```

## Customizing per-endpoint thresholds

Independent of which adapter is selected — the same override shape works for `memory` or `redis`:

```js
await initIdentityProvider({
  // ...
  rateLimiting: {
    adapter: 'redis',
    redis: { host: '127.0.0.1', port: 6379 },

    // Tighten login-by-IP beyond the 10/15min default; leave everything
    // else (loginByEmail, passwordReset, mfaChallenge, refreshToken, magicLink)
    // at their defaults by simply not mentioning them.
    login: { max: 5, windowSeconds: 15 * 60 },

    // Loosen refresh — a mobile app with many background refreshes might
    // legitimately need more than the 30/min default.
    refreshToken: { max: 120, windowSeconds: 60 },
  },
});
```

## Disabling entirely (already rate-limited upstream)

If a gateway/CDN in front of your service (Cloudflare, an API gateway) already enforces rate
limits, running this layer too is redundant — not harmful, but it costs a storage round-trip on
every rate-limited request for no benefit:

```js
await initIdentityProvider({
  // ...
  rateLimiting: { enabled: false },
});
```

## Related

- [Rate Limiter Interface](../api/rate-limiter-interface.md) — the default per-endpoint table,
  and why backend errors fail *open* here (unlike the cache layer's revocation checks, which fail
  closed).
- [Redis Cache Adapter example](redis-cache-adapter.md) — the connection-sharing partner.
- [Errors](../api/errors.md) — `RATE_LIMIT_EXCEEDED` (429).
