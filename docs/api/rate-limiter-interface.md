---
title: "Rate Limiter Interface"
package: "@okeav/idp-core"
category: "api-reference"
tags: ["rate-limiting", "redis", "security"]
description: "The RateLimiter contract, built-in memory/Redis/noop adapters, per-endpoint default rules, and the per-key fail-closed/fail-open backend behavior."
---

# Rate Limiter Interface

Request-rate limiting throttles the *rate* of requests to a handful of sensitive endpoints within
a rolling fixed window, regardless of whether individual requests succeed. It's a **distinct
concern** from `security.maxFailedLoginAttempts` (which permanently locks one account after N
wrong passwords, tracked on the user record — see [Password & Email Auth](password-email-auth.md))
and from the per-account MFA lockout (`config.mfa.lockout`, counted in storage and independent of
`rateLimiting.enabled` — see [MFA](mfa.md#per-account-lockout)).

## `RateLimiter` contract

```ts
interface RateLimitResult { allowed: boolean; remaining: number; resetAt: number /* epoch ms */ }

interface RateLimiter {
  check(key: string): Promise<RateLimitResult>;    // read-only peek, does not consume an attempt
  increment(key: string, opts: { max: number; windowSeconds: number }): Promise<RateLimitResult>; // atomically consumes one attempt, creating the window if absent
  reset(key: string): Promise<void>;                // clears a key (e.g. on successful login)
}
```

`createRateLimiter(config, sharedRedisClient?)` (internal) wraps the selected adapter in a
key-prefixing decorator (`config.rateLimiting.keyPrefix`, default `'ratelimit:'`).

## `config.rateLimiting`

```ts
{
  enabled?: boolean;              // default true
  adapter?: 'memory' | 'redis';   // default 'memory'
  keyPrefix?: string;             // default 'ratelimit:'
  redis?: { host; port; password?; db? }; // only read if adapter === 'redis' and no shared client
  login?: RateLimitRule; loginByEmail?: RateLimitRule; passwordReset?: RateLimitRule;
  mfaChallenge?: RateLimitRule; refreshToken?: RateLimitRule; magicLink?: RateLimitRule;
}
// RateLimitRule = { max?: number; windowSeconds?: number }
```

Set `enabled: false` to disable entirely (e.g. you already rate-limit at a gateway/CDN layer —
running it twice is redundant, not harmful, but the extra storage round-trip on every request is
pure overhead if a layer in front already enforces it). When disabled, every check is served by
`NoopRateLimiter` — always `{ allowed: true, remaining: Infinity, resetAt: 0 }`, no storage
touched.

### Default per-endpoint rules

| Rule | Endpoint | Default |
|---|---|---|
| `login` | Login, per IP | 10 / 15 min |
| `loginByEmail` | Login, per email | 5 / 15 min |
| `passwordReset` | Password reset request, per IP | 3 / hour |
| `mfaChallenge` | MFA challenge verification (`/mfa/verify` and `/webauthn/mfa/verify`, one shared key), per IP | 5 / 15 min |
| `refreshToken` | Refresh token, per IP | 30 / min |
| `magicLink` | Magic-link request, per IP | 3 / hour |

Override any rule under `config.rateLimiting.<name>` — each takes `{ max, windowSeconds }`,
merged over the default (partial overrides work).

**Not env-configurable** — only `IDP_RATE_LIMIT_ENABLED`/`IDP_RATE_LIMIT_ADAPTER` are read by
`configFromEnv()`. Override per-rule thresholds in code.

## `enforceRateLimit(state, key, rule, opts?)` (internal pattern)

```ts
enforceRateLimit(state, key: string, rule: { max: number; windowSeconds: number }, opts?: { failMode?: 'open' | 'closed' })
```

Every rate-limited handler calls this internally before doing work, e.g.
`` enforceRateLimit(state, `login:ip:${req.ip}`, config.rateLimiting.login, { failMode: 'closed' }) ``.
Throws `RATE_LIMIT_EXCEEDED` (429) when the limit is exceeded. `failMode` decides what happens
when the **backend** errors (Redis down, timeout):

## Backend errors: fail closed on credential checks, open elsewhere

- **`'closed'`** — the request is rejected with 503 `RATE_LIMITER_UNAVAILABLE` (logged at
  `error`). Used for every key guarding a credential check, so an attacker who can knock the
  limiter over doesn't get unlimited guesses: `login` and `loginByEmail`, `mfaChallenge` (TOTP and
  WebAuthn MFA verify), `passwordReset`, and `magicLink`.
- **`'open'`** (the default) — the request is allowed through and the error is logged
  (`logger.warn`). Kept for limits whose job is load-shedding rather than brute-force protection:
  `refreshToken`.

Before 0.3.0 every key failed open.

## `MemoryRateLimiter`

```ts
class MemoryRateLimiter implements RateLimiter {
  constructor(opts?: { sweepIntervalMs?: number }); // default 60_000
  close(): void;
}
```

Zero-config default. Fixed-window counter, **single-process only** — same caveat as
`MemoryCacheAdapter`: fine for local dev, wrong for horizontally-scaled deployments (each instance
enforces its own independent limit, effectively multiplying the real limit by instance count).

## `RedisRateLimiter` / `createRedisRateLimiter(opts)`

```ts
class RedisRateLimiter implements RateLimiter {
  constructor(opts: { redis: IORedisClient });
}
function createRedisRateLimiter(opts: {
  redis?: IORedisClient; host?: string; port?: number; password?: string; db?: number;
}): Promise<RedisRateLimiter>
```

Uses an atomic Lua script (`INCR` + conditional `EXPIRE` on first increment) so a concurrent burst
of requests can never race past the check the way a separate `INCR`+`EXPIRE` pair could. `ioredis`
is a peer dependency, dynamically imported only when this adapter is used.

**Connection sharing**: if `config.rateLimiting.redis.host` isn't explicitly set and
`config.cache.adapter === 'redis'`, the rate limiter automatically reuses the cache adapter's
already-connected `ioredis` client (via `cache.redisClient`) instead of opening a second
connection. Set `config.rateLimiting.redis` explicitly to use a separate Redis instance/database.

## `NoopRateLimiter`

Used automatically when `config.rateLimiting.enabled === false`. Also directly exported for
consumers who want the same "always allow" adapter shape for testing.

## Related

- [Cache Interface](cache-interface.md) — connection-sharing partner, and the fail-closed
  revocation check.
- [Errors](errors.md) — `RATE_LIMIT_EXCEEDED` (429), `RATE_LIMITER_UNAVAILABLE` (503).
- [Redis Rate Limiter example](../examples/redis-rate-limiter-adapter.md)
