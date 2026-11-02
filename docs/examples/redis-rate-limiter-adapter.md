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
[Rate Limiter Interface](../api/rate-limiter-interface.md) for the full contract and what a
backend error does (fail-closed on every limit except refresh, which fails open).

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
    // Omit to share the cache adapter's connection instead (requires cache.adapter 'redis' —
    // see redis-cache-adapter.md). With neither, startup fails rather than connecting to localhost.
    redis: {
      host: '127.0.0.1',
      port: 6379,
      // username: 'idp',  // Redis 6 ACL user, if any
      // password: '...',
      // tls: true,        // or ioredis TLS options — for managed Redis / anything off the local network
    },
  },
});
```

Counters are incremented with an atomic Lua script (`INCR`, then `EXPIRE` whenever the key has no
expiry), so a concurrent burst can't race past a limit, and a key can't be left without a TTL — and
its owner limited forever — if an `EXPIRE` ever failed. Windows are whole seconds (every rule must
use positive integer `max`/`windowSeconds`; startup refuses anything else).

## Customizing per-endpoint thresholds

Independent of which adapter is selected — the same override shape works for `memory` or `redis`:

```js
await initIdentityProvider({
  // ...
  rateLimiting: {
    adapter: 'redis',
    redis: { host: '127.0.0.1', port: 6379 },

    // Tighten login-by-IP beyond the 10/15min default; leave every other
    // rule (loginByEmail, passwordReset, mfaChallenge, register, oauth2Token, ...)
    // at its default by simply not mentioning it.
    login: { max: 5, windowSeconds: 15 * 60 },

    // Loosen refresh — a mobile app with many background refreshes might
    // legitimately need more than the 30/min default.
    refreshToken: { max: 120, windowSeconds: 60 },

    // A campus or office network behind one NAT address registers many users at once.
    register: { max: 50, windowSeconds: 60 * 60 },
  },
});
```

The full list of rules and their defaults is in
[Rate Limiter Interface](../api/rate-limiter-interface.md#default-per-endpoint-rules).

## Behind a proxy: set `trust proxy`

Per-IP limits key on `req.ip` (IPv6 clients by their /64). Behind a load balancer or reverse proxy,
tell Express how many hops to trust, or every client shares the proxy's IP — and never set it to
`true`, which lets any client choose its own IP through `X-Forwarded-For`:

```js
app.set('trust proxy', 1); // one proxy hop; or the proxies' subnet, e.g. '10.0.0.0/8'
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

Only do this if the upstream layer covers every limited endpoint, including the ones guarding
codes and secrets (`/register/verify-email`, `/oauth2/token*`, `/internal/service-keys`) — not just
login.

## Related

- [Rate Limiter Interface](../api/rate-limiter-interface.md) — the default per-endpoint table,
  and why a Redis outage rejects every limited request except refresh with 503
  `RATE_LIMITER_UNAVAILABLE` (fail-closed) but lets refresh through (fail-open).
- [Redis Cache Adapter example](redis-cache-adapter.md) — the connection-sharing partner.
- [Errors](../api/errors.md) — `RATE_LIMIT_EXCEEDED` (429), `RATE_LIMITER_UNAVAILABLE` (503).
