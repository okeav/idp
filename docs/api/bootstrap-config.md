---
title: "Bootstrap & Configuration"
package: "@okeav/idp-core"
category: "api-reference"
tags: ["config", "bootstrap", "setup"]
description: "initIdentityProvider(), configFromEnv(), and the full IdpConfig shape with defaults."
---

# Bootstrap & Configuration

`@okeav/idp-core` keeps all wired state (storage, cache, signing keys, hooks, logger) in a
module-level singleton. Call `initIdentityProvider(config)` exactly once at startup, before
mounting any handler or middleware this package exports — every export reads the singleton
internally via `getState()`, so you never thread config through your own routes.

## `initIdentityProvider(config)`

```ts
function initIdentityProvider(config: IdpConfig): Promise<{
  config: IdpConfig;
  logger: Logger;
  storage: StorageContract;
  cache: CacheAdapter;
  hooks: HookMap;               // merged + webhook-wrapped hooks actually in effect
  rateLimiter: RateLimiter;
  webhookDispatcher: WebhookDispatcher;
  signingKeys: KeyRegistry;
  hashEmail: (email: string) => string;
  normalizeEmail: (email: string) => string;
}>
```

The full return value is the exact same object stored in the module-level singleton — every field
above is present, not just the four most commonly used ones (`config`/`logger`/`storage`/`cache`).

Wires, in order: config defaults (`withDefaults`) → logger → webhook dispatcher → hooks
(wrapped so notification hooks also fire webhook deliveries) → cache adapter → rate limiter
(sharing the cache adapter's Redis connection when applicable) → signing-key registry →
storage (Mongo by default, or `config.storage.factory` if provided).

Returns a read-only-ish view of the wired state for consumers who want direct access (e.g. to
close the Mongo connection in tests). You don't need to hold onto or pass around this return
value — every handler export reads the same underlying state.

**Throws** (plain `Error`, not `IdpError` — these are startup/config failures, not request-time
errors):

| Condition | Message |
|---|---|
| `config.issuer` missing | `config.issuer is required` |
| Neither `config.mongo` nor `config.storage.factory` provided | `config.mongo (uri or connection) is required unless config.storage.factory is provided` |
| `config.signingKeys.keys` empty | `config.signingKeys.keys is required (at least one ACTIVE signing key)` |
| `config.security.emailHashPepper` missing | `config.security.emailHashPepper is required` |
| `config.security.tokenHashSecret` missing | `config.security.tokenHashSecret is required` |

**Throws** `IdpError({ code: 'MONGO_TRANSACTIONS_UNSUPPORTED', httpStatus: 500 })` if the target
MongoDB deployment doesn't support transactions (see [Repository Adapters](repository-adapters.md)
— login, MFA-verify, and SSO callback each write through a real Mongo transaction, which requires
a replica set or sharded cluster). Set `mongo.skipTransactionCheck: true` to skip this startup
probe (e.g. a CI job reusing a known-good cluster).

## `configFromEnv(env?)`

```ts
function configFromEnv(env?: NodeJS.ProcessEnv): IdpConfig
```

Optional convenience that builds an `IdpConfig` from `process.env` variables matching
`.env.example` in the package repo. The package never reads `process.env` on its own initiative
— using this helper is entirely your choice. Hand `initIdentityProvider()` a plain object built
any way you like (Infisical, AWS Secrets Manager, hardcoded for tests, etc.) instead if you
prefer.

Notable env-var behavior:
- `IDP_SIGNING_KEY_CURRENT_KID`/`_PRIVATE_B64`/`_PUBLIC_B64` build one `ACTIVE` signing key;
  `IDP_SIGNING_KEY_PREVIOUS_*` (optional) builds a second `ROTATING` key for graceful rotation.
- `IDP_SSO_*_CLIENT_ID` gates whether each `oauthProviders.*` entry is populated at all — omit a
  provider's client ID and that provider is left `undefined`, not defaulted.
- `IDP_WEBAUTHN_RP_ID` gates whether `webauthn` config is populated — omit it and `webauthn: {}`.
- `IDP_WEBHOOK_URL` supports a single endpoint only; configure `config.webhooks.endpoints`
  directly in code for multiple.
- Per-rule rate-limit thresholds (`login`, `passwordReset`, etc.) are **not** env-configurable —
  only `IDP_RATE_LIMIT_ENABLED`/`IDP_RATE_LIMIT_ADAPTER`. Override the per-rule `{max,
  windowSeconds}` pairs in code.

## `IdpConfig` shape

```ts
interface IdpConfig {
  issuer: string; // required — this IDP's URL, used as the JWT `iss` claim

  // Required unless storage.factory is provided.
  mongo?: ({ uri: string } | { connection: unknown }) & { skipTransactionCheck?: boolean };

  // Plug in a non-Mongo storage adapter without idp-core ever importing it.
  storage?: {
    factory?: (resolvedConfig: IdpConfig, deps: {
      hashEmail: (email: string) => string;
      normalizeEmail: (email: string) => string;
    }) => Promise<StorageContract>;
  };

  cache?: {
    adapter?: 'memory' | 'redis';       // default 'memory'
    keyPrefix?: string;                  // default 'idp:'
    redis?: { host: string; port: number; password?: string; db?: number; keepAliveMs?: number };
  };

  signingKeys: { keys: Record<string, SigningKeyEntry> }; // required — at least one ACTIVE/ROTATING key

  cookies?: {
    secure?: boolean;    // default: NODE_ENV !== 'development'
    sameSite?: 'lax' | 'strict' | 'none'; // default 'lax'
    domain?: string;
  };

  session?: {
    reresolveClaimsOnRefresh?: boolean; // default false — see password-email-auth.md's Refresh section
  };

  ttls?: Partial<{ /* see table below — all in seconds */ }>;

  security: {
    emailHashPepper: string;   // required — HMAC key for the email blind index, non-rotating
    tokenHashSecret: string;   // required — HMAC key for hashing opaque tokens at rest
    maxFailedLoginAttempts?: number;  // default 5
    accountLockDurationMs?: number;   // default 1_800_000 (30 min)
    bcryptRounds?: number;            // default 12
  };

  mfa?: { issuerLabel?: string; recoveryCodeCount?: number };       // defaults: 'App', 10
  magicLink?: { allowSignupViaMagicLink?: boolean };                // default true
  webauthn?: { rpID?: string; rpName?: string; origin?: string | string[] }; // no defaults — opt-in
  oauthProviders?: { google?, github?, microsoft?, apple?, linkedin? };     // see SSO doc
  sso?: { baseCallbackUrl?: string; allowedRedirectOrigins?: string[] };
  serviceMesh?: { bootstrapSecret?: string; tokenMode?: 'token' | 'secret' | 'both'; ownServiceName?: string; sharedSecret?: string }; // tokenMode default 'both'

  rateLimiting?: {
    enabled?: boolean;              // default true
    adapter?: 'memory' | 'redis';   // default 'memory'
    keyPrefix?: string;             // default 'ratelimit:'
    redis?: { host; port; password?; db? };
    login?: RateLimitRule; loginByEmail?: RateLimitRule; passwordReset?: RateLimitRule;
    mfaChallenge?: RateLimitRule; refreshToken?: RateLimitRule; magicLink?: RateLimitRule;
  };

  webhooks?: {
    endpoints?: Array<{ url: string; secret: string }>; // default [] (disabled)
    maxAttempts?: number;      // default 5
    retryBaseDelayMs?: number; // default 500 (doubles each attempt)
    timeoutMs?: number;        // default 5000
  };

  hooks?: AuthHooks;
  logger?: Logger; // default: console-backed logger with { info, warn, error, debug }(obj, msg)
}
```

### `SigningKeyEntry`

```ts
interface SigningKeyEntry {
  privateKey?: string; // PEM or base64-PEM. Omit on a verify-only key (e.g. RETIRED).
  publicKey: string;   // PEM or base64-PEM.
  status: 'ACTIVE' | 'ROTATING' | 'RETIRED' | 'REVOKED';
}
```

Exactly one key should normally be `ACTIVE`; `getActiveSigningKey()` (used internally for every
token issuance) prefers `ACTIVE` and falls back to `ROTATING` if none is `ACTIVE`. Both `ACTIVE`
and `ROTATING` keys are published in the JWKS; `/keys/:kid` additionally serves `RETIRED` keys
(rejecting `REVOKED` with 403). `verifyWithAnyKey()` (the function every access-token/ID-token
verification actually goes through) resolves a token's key by its `kid` via `getPublicKeyByKid()`,
which enforces the same rule: `ACTIVE`/`ROTATING`/`RETIRED` all still verify (a `RETIRED` key keeps
verifying tokens issued while it was active — a rotation grace period, not revocation), but a
**`REVOKED`** key's `kid` resolves to nothing, so a token signed with it fails verification
(`INVALID_TOKEN`, 401) even though its `kid` is still present in the registry. `REVOKED` is the one
status that actually invalidates previously-issued tokens; the others only affect whether the key
is used for *new* signing/JWKS publication. See [Tokens & Signing (RS256)](tokens-rs256.md).

### Default TTLs (`config.ttls`, all seconds)

| Field | Default |
|---|---|
| `accessToken` | 3600 (1h) |
| `idToken` | 3600 (1h) |
| `refreshToken` | 2,592,000 (30d) |
| `internalToken` | 30 |
| `authCode` | 600 (10m) |
| `revocationCache` | 3600 (1h) |
| `refreshTokenCache` | 3600 (1h) |
| `passwordReset` | 900 (15m) |
| `emailVerification` | 86,400 (24h) |
| `magicLink` | 900 (15m) |
| `mfaChallenge` | 300 (5m) |
| `ssoState` | 600 (10m) |
| `ssoExchange` | 120 (2m) |
| `discoveryCache` | 3600 (1h) |
| `webauthnChallenge` | 300 (5m) |

## Claims are opaque

`issueAccessToken({ sub, email, claims })` — `claims` is whatever object you pass. It comes back
untouched as `req.auth.claims` after `authContextMiddleware`. This package never validates its
shape and ships no scope-matching or permission-checking logic. For login flows that mint a
session on your behalf (password login, MFA-verify, SSO callback, magic-link verify, WebAuthn
login), configure `hooks.resolveAuthContext(user, ctx)` to build that `claims` object — called
synchronously right before token issuance, defaults to `() => ({})`.

## What this package deliberately does not do

- No RBAC decisioning — no scope catalogue, wildcard permission matcher, or `requirePermission()`.
- No message bus, SMTP, or push integration — wire your own inside [hooks](hooks-events.md is
  covered inline in each auth-flow doc; see the Event hooks table below).
- No secrets-vault client — resolve config values before calling `initIdentityProvider()`.
- No QR-code rendering for MFA — `setupMfaHandler` returns the raw `otpauth://` URI.

## Event hooks (`config.hooks`)

All hooks are optional and default to no-ops. Every hook in the table below **except
`resolveAuthContext`** is awaited-but-never-thrown: a hook that throws is logged (`logger.warn`)
and swallowed, never breaking the request it's attached to (`safeInvokeHook` in
`src/hooks/index.js`).

**`resolveAuthContext` is the one exception — it is not wrapped in that safety net.** It's called
directly (`await hooks.resolveAuthContext(user, ctx)`, no try/catch) from every login path that
mints a session. A throwing/rejecting `resolveAuthContext` propagates and turns that login/SSO/
magic-link/WebAuthn request into an error response instead of being swallowed. It also isn't in
`defaultHooks()` at all — omitting it entirely is equivalent to it resolving `{}` (no claims), not
to a registered no-op.

| Hook | Fires on | Payload |
|---|---|---|
| `onAuditLog(event)` | Every audit-worthy action | `{ action, ...eventFields, timestamp }` — `action` values include `REGISTERED`, `LOGIN`, `LOGOUT`, `LOGOUT_ALL`, `EMAIL_VERIFIED`, `VERIFICATION_TOKEN_REGENERATED`, `PASSWORD_RESET`, `PASSWORD_CHANGED`, `ACCOUNT_LOCKED`, `PROFILE_UPDATED`, `ACCOUNT_DELETED`, `SESSION_REVOKED`, `SESSIONS_REVOKED_ALL`, `TOKEN_REFRESHED`, `MAGIC_LINK_REQUESTED`, `MAGIC_LINK_LOGIN`, `WEBAUTHN_CREDENTIAL_REGISTERED`, `WEBAUTHN_LOGIN`, `MFA_VERIFIED`, plus OAuth2/OIDC/SSO/MFA-setup actions |
| `onVerificationEmailRequested` | Registration and resend-verification | `{ email, firstName?, lastName?, verificationToken, verificationCode }` |
| `onPasswordResetRequested` | Forgot-password | `{ email, resetToken, firstName?, lastName? }` |
| `onPasswordChanged` | Password change/reset completed | `{ userId, email, firstName, lastName, locale, when, deviceInfo, ipAddress }` |
| `onSuspiciousActivityDetected` | Account locked after too many failed logins | `{ userId, email, firstName, lastName, locale, when, failedAttempts, unlocksAt }` |
| `onNewDeviceLogin` | Login from a browser/OS combination not seen before for this user | `{ userId, email, firstName, lastName, locale, when, deviceInfo, ipAddress }` |
| `onMagicLinkRequested` | Magic-link login requested | `{ email, magicLinkToken, firstName?, lastName?, isNewUser }` |
| `resolveAuthContext(user, ctx)` | Password login, MFA-verify, SSO callback, magic-link verify, WebAuthn login | Returns `{ claims }`; `ctx = { isNewUser, isNewLink?, method?, provider?, extra? }` |

This package never talks to a message bus, SMTP server, or push provider directly — wire your own
inside these hooks. See [Outbound Webhooks](webhooks.md) for the additive HTTP-delivery mechanism
built on top of these same hooks.

## Related

- [Errors](errors.md) — every thrown error is an `IdpError`.
- [Tokens & Signing (RS256)](tokens-rs256.md)
- [Repository Adapters](repository-adapters.md) — the `storage.factory` extension point.
- [Cache Interface](cache-interface.md), [Rate Limiter Interface](rate-limiter-interface.md)
- [Outbound Webhooks](webhooks.md)
