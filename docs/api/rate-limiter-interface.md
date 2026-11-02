---
title: "Rate Limiter Interface"
package: "@okeav/idp-core"
category: "api-reference"
tags: ["rate-limiting", "redis", "security"]
description: "The RateLimiter contract, built-in memory/Redis/noop adapters, per-endpoint default rules, how keys are built, and the per-key fail-closed/fail-open backend behavior."
---

# Rate Limiter Interface

Request-rate limiting throttles the *rate* of requests to the sensitive endpoints within a fixed
window, regardless of whether individual requests succeed. It's a **distinct concern** from
`security.maxFailedLoginAttempts` (which locks one account after N wrong passwords, tracked on the
user record — see [Password & Email Auth](password-email-auth.md)), from the per-account MFA
lockout (`config.mfa.lockout` — see [MFA](mfa.md#per-account-lockout)) and from the per-account
email-verification lockout (`security.verificationCodeLockout`). Both lockouts are counted in
storage and are independent of `rateLimiting.enabled`.

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
  redis?: { host; port; username?; password?; db?; tls? }; // only read if adapter === 'redis'; host set → its own connection
  login?: RateLimitRule; loginByEmail?: RateLimitRule;
  passwordReset?: RateLimitRule; passwordResetByEmail?: RateLimitRule;
  mfaChallenge?: RateLimitRule; refreshToken?: RateLimitRule;
  magicLink?: RateLimitRule; magicLinkByEmail?: RateLimitRule;
  register?: RateLimitRule; emailVerification?: RateLimitRule; verificationEmailByEmail?: RateLimitRule;
  webauthnAuthentication?: RateLimitRule; oauth2Token?: RateLimitRule;
  ssoInitiate?: RateLimitRule; serviceKeyRegistration?: RateLimitRule;
}
// RateLimitRule = { max?: number; windowSeconds?: number }
```

Set `enabled: false` to disable entirely (e.g. you already rate-limit at a gateway/CDN layer —
running it twice is redundant, not harmful, but the extra storage round-trip on every request is
pure overhead if a layer in front already enforces it). When disabled, every check is served by
`NoopRateLimiter` — always `{ allowed: true, remaining: Infinity, resetAt: 0 }`, no storage
touched. (Think twice: several of these limits — `emailVerification`, `oauth2Token`,
`serviceKeyRegistration` — bound guesses at codes and secrets, so the gateway must cover them too.)

### Default per-endpoint rules

| Rule | Endpoint | Key | Default | Backend error |
|---|---|---|---|---|
| `login` | `POST /login` | per IP | 10 / 15 min | closed |
| `loginByEmail` | `POST /login` | per address | 5 / 15 min | closed |
| `passwordReset` | `POST /password/forgot` | per IP | 3 / hour | closed |
| `passwordResetByEmail` | `POST /password/forgot` | per address | 3 / hour | closed |
| `mfaChallenge` | `/mfa/verify` and `/webauthn/mfa/verify` (one shared key) | per IP | 5 / 15 min | closed |
| `refreshToken` | `POST /refresh` | per IP | 30 / min | **open** |
| `magicLink` | `POST /magic-link/request` | per IP | 3 / hour | closed |
| `magicLinkByEmail` | `POST /magic-link/request` | per address | 3 / hour | closed |
| `register` | `POST /register` and `/register/resend-verification` | per IP | 10 / hour | closed |
| `emailVerification` | `POST /register/verify-email` | per IP | 20 / 15 min | closed |
| `verificationEmailByEmail` | Every verification email sent to one address (register, re-register, resend) | per address | 3 / hour | closed |
| `webauthnAuthentication` | `POST /webauthn/authentication/options` and `/verify` (a login is two requests) | per IP | 60 / 5 min | closed |
| `oauth2Token` | `/oauth2/token`, `/oauth2/token/revoke`, `/oauth2/token/introspect` | per IP | 120 / min | closed |
| `ssoInitiate` | `GET /sso/:provider` | per IP | 30 / 5 min | closed |
| `serviceKeyRegistration` | `POST /internal/service-keys` (bootstrap-secret guesses) | per IP | 20 / 15 min | closed |

Override any rule under `config.rateLimiting.<name>` — each takes `{ max, windowSeconds }`,
merged over the default (partial overrides work). After merging, every rule must have positive
integer `max` and `windowSeconds`, or `initIdentityProvider()` throws (a fractional window could
leave a Redis key without an expiry).

**Not env-configurable** — only `IDP_RATE_LIMIT_ENABLED`/`IDP_RATE_LIMIT_ADAPTER` are read by
`configFromEnv()`. Override per-rule thresholds in code.

## Keys

- **Per-IP keys** use `req.ip`, normalised: IPv4 as-is, an IPv4-mapped IPv6 address
  (`::ffff:a.b.c.d`) as its IPv4 address, and any other IPv6 address collapsed to its **/64 prefix**
  — a single host is routinely given a whole /64, so keying on the full address would give one
  client 2^64 fresh buckets.
- **Per-address keys** use the email's keyed hash (the same HMAC as the email lookup index, under
  `security.emailHashPepper`), never the address itself, so Redis and logs don't hold emails.

`req.ip` is only as trustworthy as Express's `trust proxy` setting. Set it to your proxy hop count
or subnet (`app.set('trust proxy', 1)`), **never `true`** — that trusts any client-supplied
`X-Forwarded-For`, letting a client pick a fresh IP per request. See
[Bootstrap & Config](bootstrap-config.md#client-ips-and-trust-proxy).

## `enforceRateLimit(state, key, rule, opts?)` (internal pattern)

```ts
enforceRateLimit(state, key: string, rule: { max: number; windowSeconds: number }, opts?: { failMode?: 'open' | 'closed' })
```

Every rate-limited handler calls this internally before doing work, e.g.
`` enforceRateLimit(state, `login:ip:${ipKey(req.ip)}`, config.rateLimiting.login, { failMode: 'closed' }) ``.
Throws `RATE_LIMIT_EXCEEDED` (429) when the limit is exceeded. `failMode` decides what happens
when the **backend** errors (Redis down, timeout, a full `MemoryRateLimiter`):

## Backend errors: fail closed everywhere except refresh

- **`'closed'`** — the request is rejected with 503 `RATE_LIMITER_UNAVAILABLE` (logged at
  `error`). Used for every limit in the table above except `refreshToken`: an attacker who can
  knock the limiter over must not get unlimited guesses as a result.
- **`'open'`** (the function's default) — the request is allowed through and the error is logged
  (`logger.warn`). Kept only for `refreshToken`, whose job is load-shedding rather than
  brute-force protection.

Before 0.3.0 every key failed open.

## `MemoryRateLimiter`

```ts
class MemoryRateLimiter implements RateLimiter {
  constructor(opts?: { sweepIntervalMs?: number; maxKeys?: number }); // defaults 60_000, 500_000
  close(): void;
}
```

Zero-config default. Fixed-window counter, **single-process only** — same caveat as
`MemoryCacheAdapter`: fine for local dev, wrong for horizontally-scaled deployments (each instance
enforces its own independent limit, effectively multiplying the real limit by instance count).

It tracks at most `maxKeys` keys (default 500,000). When full — after sweeping expired windows — a
**new** key is refused with an error, which the fail-closed call sites turn into 503
`RATE_LIMITER_UNAVAILABLE`. It deliberately doesn't evict: eviction would let an attacker flush
their own counter by flooding distinct keys. Existing keys keep counting normally.

## `RedisRateLimiter` / `createRedisRateLimiter(opts)`

```ts
class RedisRateLimiter implements RateLimiter {
  constructor(opts: { redis: IORedisClient });
}
function createRedisRateLimiter(opts: {
  redis?: IORedisClient;
  host?: string; port?: number; username?: string; password?: string; db?: number; tls?: boolean | object;
}): Promise<RedisRateLimiter>
```

Uses an atomic Lua script (`INCR`, then `EXPIRE` whenever the key has no expiry) so a concurrent
burst of requests can never race past the check the way a separate `INCR`+`EXPIRE` pair could.
Setting the expiry whenever it's missing — not only on the first increment — means a failed
`EXPIRE` can't leave a key (and its owner) limited forever. Windows are rounded up to whole seconds.
`ioredis` is a peer dependency, dynamically imported only when this adapter is used.

**Connection sharing**: if `config.rateLimiting.redis.host` isn't set, the rate limiter reuses the
cache adapter's already-connected `ioredis` client (via `cache.redisClient`) instead of opening a
second connection — which requires `config.cache.adapter === 'redis'`. With neither, startup fails
(`Rate limiter adapter "redis" needs config.rateLimiting.redis.host, or config.cache.adapter "redis"
to share its connection`) rather than silently connecting to localhost. Set
`config.rateLimiting.redis` explicitly to use a separate Redis instance/database.

## `NoopRateLimiter`

Used automatically when `config.rateLimiting.enabled === false`. Also directly exported for
consumers who want the same "always allow" adapter shape for testing.

## Related

- [Cache Interface](cache-interface.md) — connection-sharing partner, and the fail-closed
  revocation check.
- [Errors](errors.md) — `RATE_LIMIT_EXCEEDED` (429), `RATE_LIMITER_UNAVAILABLE` (503).
- [Redis Rate Limiter example](../examples/redis-rate-limiter-adapter.md)
