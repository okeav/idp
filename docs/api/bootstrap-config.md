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
  mfaCipher: SecretCipher | null;        // built from config.mfa (see MFA secret encryption below)
  attemptCounters: AttemptCounterRepository; // storage's, or the in-process fallback
}>
```

The full return value is the exact same object stored in the module-level singleton — every field
above is present, not just the four most commonly used ones (`config`/`logger`/`storage`/`cache`).
(The published type declares only those four.)

Wires, in order: config defaults (`withDefaults`) → validation of `security` and every
`rateLimiting` rule (and the dummy password hash, generated at `security.bcryptRounds`) → logger → MFA secret cipher + config validation, lockout settings, SSO
settings, `hookTimeoutMs`, `oauth2.requirePkce`, `cookies`, `issuer` + `ttls` + secret separation, `oidc.endSessionConfirmationUrl`, `clock`, service-mesh secrets, `serviceMesh.rotationGraceSeconds`, `session.*` numbers (all before anything connects,
so bad config fails the boot) → webhook dispatcher (validates every endpoint) → hooks (wrapped so
notification hooks also fire webhook deliveries) → cache adapter → rate limiter (sharing the cache
adapter's Redis connection when applicable) → signing-key registry (every key validated) → storage
(Mongo by default, or `config.storage.factory` if provided) → storage contract check → clock-skew
check against the database (see [Clock skew](#clock-skew-configclock)).

Some storage capabilities are optional, and an adapter missing them still boots with a
`logger.warn` at startup: no `attemptCounterRepository` → the attempt budgets (the per-account MFA
lockout, the password-login lockout, the verification-code and password-change limits) count
in-process only (not shared across instances); no `userRepository.claimTotpStep` /
`consumeRecoveryCode` → TOTP replay and recovery-code reuse are checked with a non-atomic
read-then-write; no `storage.databaseTime()` → clock skew isn't checked
(see [Clock skew](#clock-skew-configclock)). See [Repository Adapters](repository-adapters.md).

The **required** methods are checked as soon as storage is built (since 0.4.0): an adapter missing
any method listed in `REQUIRED_STORAGE_METHODS` (`src/storage/interfaces.js`), or `close`, is closed
and `initIdentityProvider()` throws, naming every missing method — instead of failing in the middle
of the first request that needs one.

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
| `config.security.emailHashPepper` / `tokenHashSecret` missing | `config.security.<name> is required` |
| `emailHashPepper` / `tokenHashSecret` shorter than 32 characters | `config.security.<name> must be a random string of at least 32 characters` |
| `tokenHashSecret` equal to `emailHashPepper` | `config.security.tokenHashSecret and emailHashPepper must be different secrets` |
| `security.previousTokenHashSecrets` not an array | `config.security.previousTokenHashSecrets must be an array of strings` |
| A `previousTokenHashSecrets` entry under 32 characters, equal to the current `tokenHashSecret` or to `emailHashPepper`, or listed twice | `config.security.previousTokenHashSecrets[i] must be a string of at least 32 characters` / `config.security.previousTokenHashSecrets[i] is the current tokenHashSecret` / `config.security.previousTokenHashSecrets[i] must not be the emailHashPepper` / `config.security.previousTokenHashSecrets has duplicates` |
| `issuer` not an `https` URL (`http` only for `localhost`, `127.0.0.1`, `[::1]`, or any `http` with `NODE_ENV=development`) | `config.issuer must be an https URL (http only for localhost) — got ...` |
| Any `ttls.*` value that isn't a positive integer (seconds) | `config.ttls.<name> must be a positive integer of seconds (got ...)` |
| `session.verifyOnEachRequest: false` and `ttls.revocationCache` < `ttls.accessToken` (a revocation marker would expire before the token it revokes) | `config.ttls.revocationCache must be at least ttls.accessToken when session.verifyOnEachRequest is false ...` |
| `security.bcryptRounds` not an integer from 10 to 15 (from 4 with `security.allowWeakBcryptRounds: true`, for tests) | `config.security.bcryptRounds must be an integer from 10 to 15 (got ...)` |
| `security.maxFailedLoginAttempts` not a positive integer | `config.security.maxFailedLoginAttempts must be a positive integer (got ...)` |
| `security.accountLockDurationMs` not an integer ≥ 1000 | `config.security.accountLockDurationMs must be an integer of at least 1000 (got ...)` |
| A `rateLimiting.<rule>` whose `max` or `windowSeconds` isn't a positive integer | `config.rateLimiting.<rule> needs positive integer max and windowSeconds (got ...)` |
| `mfa.enabled` (default `true`) with neither `mfa.encryptionKey` nor `mfa.secretCipher`, and no `mfa.allowPlaintext` | `MFA secrets must be encrypted at rest: set config.mfa.encryptionKey ...` |
| `mfa.requireEncrypted` with neither `encryptionKey` nor `secretCipher` | `config.mfa.requireEncrypted is set but no config.mfa.encryptionKey or config.mfa.secretCipher is configured` |
| An `encryptionKey`/`previousEncryptionKeys` entry that isn't exactly the base64 of 32 bytes | `MFA encryption key must decode to exactly 32 bytes (got N) ...` / `MFA encryption key is not valid base64 ...` |
| `mfa.secretCipher` without `encrypt`/`decrypt` functions | `config.mfa.secretCipher must implement encrypt(plaintext, { context }) and decrypt(ciphertext, { context })` |
| A `mfa.lockout.*`, `security.verificationCodeLockout.*` or `security.passwordChangeLockout.*` value that isn't a positive integer | `config.<path>.<name> must be a positive integer (got ...)` |
| Any `oauthProviders.*` entry with a `clientId`, and `sso.allowedRedirectOrigins` missing/empty | `config.sso.allowedRedirectOrigins is required when SSO providers are configured (...)` |
| An `sso.allowedRedirectOrigins` entry that isn't a bare origin (`scheme://host[:port]`, no path) | `config.sso.allowedRedirectOrigins: "..." is not an origin ...` |
| SSO providers configured and `sso.baseCallbackUrl` not an absolute `http(s)` URL | `config.sso.baseCallbackUrl must be an absolute URL when SSO providers are configured` |
| SSO providers configured and `sso.baseCallbackUrl` plain `http` to anything but localhost (any `http` is allowed with `NODE_ENV=development`) | `config.sso.baseCallbackUrl must be https (http only for localhost) — provider codes are returned to it` |
| `cookies.sameSite` not `'lax'`, `'strict'` or `'none'` (case-insensitive — normalised to lower case, so `Lax` from an env var is fine) | `config.cookies.sameSite must be 'lax', 'strict' or 'none' (got ...)` |
| `cookies.sameSite: 'none'` with `cookies.secure` false (explicitly, or by the `NODE_ENV=development` default) — browsers drop such cookies | `config.cookies.sameSite 'none' requires secure cookies ...` |
| `cookies.refreshTokenInBody` not `true`, `false` or `'auto'` | `config.cookies.refreshTokenInBody must be true, false or 'auto' (got ...)` |
| `cookies.sessionPath` not an absolute path (starting with `/`, no spaces or `;`) | `config.cookies.sessionPath must be an absolute path (e.g. /auth/session) — the path the session routes are served under` |
| `cookies.trustedOrigins` not an array of exact origins (`https://app.example.com` — no path, no trailing slash; the host's case is normalised) | `config.cookies.trustedOrigins must be an array of exact origins ...` |
| `serviceMesh.bootstrapSecret`, `serviceMesh.sharedSecret` or any `serviceMesh.bootstrapSecrets` value shorter than 32 characters | `config.serviceMesh.<name> must be at least 32 characters` |
| A `serviceMesh.bootstrapSecrets` value equal to the shared `bootstrapSecret` | `config.serviceMesh.bootstrapSecrets.<name> must differ from the shared bootstrapSecret` |
| `hookTimeoutMs` not a positive integer | `config.hookTimeoutMs must be a positive integer (got ...)` |
| `oauth2.requirePkce` not `'all'` or `'public'` | `config.oauth2.requirePkce must be 'all' or 'public'` |
| `serviceMesh.rotationGraceSeconds` not an integer ≥ 0 | `config.serviceMesh.rotationGraceSeconds must be an integer >= 0 (got ...)` |
| `session.recentAuthMaxAgeSeconds` / `absoluteLifetimeSeconds` not an integer ≥ 1, or `refreshReuseGraceSeconds` not an integer ≥ 0 | `config.session.<name> must be an integer >= N (got ...)` |
| A webhook endpoint whose `url` isn't valid, isn't `https` (`http` is allowed only for localhost), whose `secret` is under 16 characters, or whose `events` isn't an array of strings | `config.webhooks.endpoints[i].<field> ...` |
| `cache.adapter: 'redis'` without `cache.redis.host` | `Cache adapter "redis" needs config.cache.redis.host` |
| `rateLimiting.adapter: 'redis'` with neither `rateLimiting.redis.host` nor a Redis cache to share | `Rate limiter adapter "redis" needs config.rateLimiting.redis.host, or config.cache.adapter "redis" to share its connection ...` |
| A signing key with an unknown `status`, an unparseable PEM, a non-RSA key, under 2048 bits, or a `privateKey` that doesn't match its `publicKey` | `config.signingKeys.keys["<kid>"] ...` |
| No `ACTIVE`/`ROTATING` key has a `privateKey` | `config.signingKeys: at least one ACTIVE (or ROTATING) key needs a privateKey to sign with` |
| `oidc.endSessionConfirmationUrl` not an `https` URL (`http` only for localhost) | `config.oidc.endSessionConfirmationUrl must be an https URL (http only for localhost)` |
| `oidc.endSessionConfirmationUrl` on an origin other than the issuer's or one of `cookies.trustedOrigins` | `config.oidc.endSessionConfirmationUrl must be on the issuer's origin or one of cookies.trustedOrigins ...` |
| `clock.maxSkewSeconds` not an integer ≥ 1, `warnSkewSeconds` not an integer ≥ 0, `checkIntervalSeconds` not an integer ≥ 10 | `config.clock.<name> must be an integer >= N (got ...)` |
| `clock.warnSkewSeconds` greater than `maxSkewSeconds` | `config.clock.warnSkewSeconds must not exceed maxSkewSeconds` |
| This server's clock differs from the database's by more than `clock.maxSkewSeconds` (adapters with `databaseTime()`; the storage is closed first) | `This server's clock is N s ahead of / behind the database's (limit M s) — token and code lifetimes would be wrong. Sync the clock (NTP).` |
| The storage adapter lacks a required method (or `close`), or provides an `attemptCounterRepository` without `get`, `recordFailure` and `reset` | `Storage adapter is missing required methods: userRepository.bumpSessionEpoch, ... — see src/storage/interfaces.js` |

**Upgrading from 0.3.x:** check your secrets (≥ 32 characters, `tokenHashSecret` ≠
`emailHashPepper`; service-mesh secrets too), `bcryptRounds` and signing keys (RSA ≥ 2048 bits,
private key matching the public key) meet these before deploying; use an `https` issuer and SSO
callback base outside localhost, whole-second `ttls`, a valid `cookies.sameSite` and exact
`cookies.trustedOrigins`; and set `sso.allowedRedirectOrigins` + `sso.baseCallbackUrl` if any SSO
provider is configured.

Startup also **warns** (`logger.warn`, no failure) when `cache` or `rateLimiting` uses Redis at a
remote host (not localhost) without `tls` — revocation markers, challenges and limits would travel
in clear.

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

**Parsing is strict (since 0.4.0).** An unset or blank variable means "use the default"; anything
else must be recognisable or `configFromEnv()` throws:

- Booleans accept `true`/`false`, `1`/`0`, `yes`/`no`, `on`/`off`, in any case. Anything else throws
  (`IDP_COOKIE_SECURE must be true/false (or 1/0, yes/no, on/off) — got "..."`). Before 0.4.0 only
  the exact string `"true"` was true, so `IDP_COOKIE_SECURE=1` silently meant insecure cookies.
- Integers must be whole numbers at or above a minimum, or it throws
  (`IDP_MAX_FAILED_LOGIN_ATTEMPTS must be an integer >= 1 — got "..."`).
- Lists are comma-separated; blanks are dropped.

| Variable | Maps to | Default / notes |
|---|---|---|
| `IDP_ISSUER` | `issuer` | |
| `IDP_MONGO_URI` | `mongo.uri` | |
| `IDP_CACHE_ADAPTER` | `cache.adapter` | `memory` |
| `IDP_CACHE_KEY_PREFIX` | `cache.keyPrefix` | `idp:` |
| `IDP_REDIS_HOST` | `cache.redis.host` | |
| `IDP_REDIS_PORT` | `cache.redis.port` | `6379` (integer ≥ 1) |
| `IDP_REDIS_USERNAME` | `cache.redis.username` | Redis 6 ACL user |
| `IDP_REDIS_PASSWORD` | `cache.redis.password` | |
| `IDP_REDIS_TLS` | `cache.redis.tls` | `false` (boolean) |
| `IDP_SIGNING_KEY_CURRENT_KID`, `_PRIVATE_B64`, `_PUBLIC_B64` | one `ACTIVE` signing key | |
| `IDP_SIGNING_KEY_PREVIOUS_KID`, `_PRIVATE_B64`, `_PUBLIC_B64` | a second, `ROTATING` key | optional |
| `IDP_COOKIE_SECURE` | `cookies.secure` | `NODE_ENV !== 'development'` |
| `IDP_COOKIE_SAME_SITE` | `cookies.sameSite` | `lax` |
| `IDP_COOKIE_DOMAIN` | `cookies.domain` | |
| `IDP_COOKIE_TRUSTED_ORIGINS` | `cookies.trustedOrigins` | list; empty |
| `IDP_COOKIE_REFRESH_TOKEN_IN_BODY` | `cookies.refreshTokenInBody` | `auto`; also accepts a boolean |
| `IDP_EMAIL_HASH_PEPPER` | `security.emailHashPepper` | required, ≥ 32 characters |
| `IDP_TOKEN_HASH_SECRET` | `security.tokenHashSecret` | required, ≥ 32 characters |
| `IDP_PREVIOUS_TOKEN_HASH_SECRETS` | `security.previousTokenHashSecrets` | list, newest first; empty — see [Rotating `tokenHashSecret`](#rotating-securitytokenhashsecret) |
| `IDP_MAX_FAILED_LOGIN_ATTEMPTS` | `security.maxFailedLoginAttempts` | `5` (integer ≥ 1) |
| `IDP_ACCOUNT_LOCK_DURATION_MS` | `security.accountLockDurationMs` | `1800000` (integer ≥ 1000) |
| `IDP_BCRYPT_ROUNDS` | `security.bcryptRounds` | `12` (integer ≥ 10; ≤ 15 is enforced at startup) |
| `IDP_MFA_ISSUER_LABEL` | `mfa.issuerLabel` | `App` |
| `IDP_MFA_RECOVERY_CODE_COUNT` | `mfa.recoveryCodeCount` | `10` (integer ≥ 1) |
| `IDP_MFA_ENABLED` | `mfa.enabled` | `true` |
| `IDP_MFA_ENCRYPTION_KEY` | `mfa.encryptionKey` | |
| `IDP_MFA_PREVIOUS_ENCRYPTION_KEYS` | `mfa.previousEncryptionKeys` | list |
| `IDP_MFA_REQUIRE_ENCRYPTED` | `mfa.requireEncrypted` | unset: `true` when a key or cipher is configured, otherwise `false` |
| `IDP_MFA_ALLOW_PLAINTEXT` | `mfa.allowPlaintext` | `false` |
| `IDP_SESSION_VERIFY_ON_EACH_REQUEST` | `session.verifyOnEachRequest` | `true` |
| `IDP_OIDC_END_SESSION_CONFIRMATION_URL` | `oidc.endSessionConfirmationUrl` | unset — see [OIDC end-session](oidc.md#get--post-sessionend--endsessionhandler) |
| `IDP_CLOCK_MAX_SKEW_SECONDS` | `clock.maxSkewSeconds` | `30` (integer ≥ 1) |
| `IDP_CLOCK_WARN_SKEW_SECONDS` | `clock.warnSkewSeconds` | `2` (integer ≥ 0) |
| `IDP_CLOCK_CHECK_INTERVAL_SECONDS` | `clock.checkIntervalSeconds` | `600` (integer ≥ 10) |
| `IDP_SSO_GOOGLE_CLIENT_ID`, `_CLIENT_SECRET` | `oauthProviders.google` | provider left `undefined` without a client id |
| `IDP_SSO_MICROSOFT_CLIENT_ID`, `_CLIENT_SECRET`, `_TENANT` | `oauthProviders.microsoft` | tenant `common` |
| `IDP_SSO_MICROSOFT_TRUST_EMAIL` | `oauthProviders.microsoft.trustEmail` | `false` |
| `IDP_SSO_GITHUB_CLIENT_ID`, `_CLIENT_SECRET` | `oauthProviders.github` | |
| `IDP_SSO_APPLE_CLIENT_ID`, `_TEAM_ID`, `_KEY_ID`, `_PRIVATE_KEY_B64` | `oauthProviders.apple` | `_PRIVATE_KEY_B64` is the base64 of the `.p8` PEM; it's decoded into `privateKeyPem` (before 0.4.0 it was passed through still encoded) |
| `IDP_SSO_LINKEDIN_CLIENT_ID`, `_CLIENT_SECRET` | `oauthProviders.linkedin` | |
| `IDP_SSO_BASE_CALLBACK_URL` | `sso.baseCallbackUrl` | required once a provider is configured |
| `IDP_SSO_ALLOWED_REDIRECT_ORIGINS` | `sso.allowedRedirectOrigins` | list; required once a provider is configured |
| `IDP_S2S_BOOTSTRAP_SECRETS` | `serviceMesh.bootstrapSecrets` | `name=secret,name=secret`; a pair without `=` throws; each ≥ 32 characters, none equal to the shared secret |
| `IDP_S2S_BOOTSTRAP_SECRET` | `serviceMesh.bootstrapSecret` | legacy shared secret; ≥ 32 characters |
| `IDP_S2S_TOKEN_MODE` | `serviceMesh.tokenMode` | `token` |
| `IDP_S2S_OWN_SERVICE_NAME` | `serviceMesh.ownServiceName` | |
| `IDP_RATE_LIMIT_ENABLED` | `rateLimiting.enabled` | `true` |
| `IDP_RATE_LIMIT_ADAPTER` | `rateLimiting.adapter` | `memory` |
| `IDP_MAGIC_LINK_ALLOW_SIGNUP` | `magicLink.allowSignupViaMagicLink` | `true` |
| `IDP_WEBAUTHN_RP_ID`, `_RP_NAME`, `_ORIGIN` | `webauthn` | populated only when `IDP_WEBAUTHN_RP_ID` is set (`rpName` default `App`); a single origin |
| `IDP_WEBHOOK_URL`, `IDP_WEBHOOK_SECRET` | `webhooks.endpoints[0]` | one endpoint only |

Everything else is code-only: `session.reresolveClaimsOnRefresh`/`recentAuthMaxAgeSeconds`/
`absoluteLifetimeSeconds`/`refreshReuseGraceSeconds`, `registration.acceptMetadata`,
`oauth2.requirePkce`, `sso.providerTimeoutMs`, `serviceMesh.allowedServiceNames`/`sharedSecret`/
`allowLegacySecretCallers`/`rotationGraceSeconds`, `webauthn.allowCredentialsByEmail`, `mfa.lockout`,
`security.verificationCodeLockout`/`passwordChangeLockout`, `hookTimeoutMs`, `ttls`, the webhook endpoint's `events` /
`includeCredentials`, and the per-rule rate-limit thresholds (override `{ max, windowSeconds }` in
code). Because the env-built webhook endpoint has no `includeCredentials`, credential fields are
stripped from its deliveries — configure `config.webhooks.endpoints` in code if that endpoint sends
your emails.

## `IdpConfig` shape

```ts
interface IdpConfig {
  issuer: string; // required — this IDP's URL (https; http only for localhost or with NODE_ENV=development), used as the JWT `iss` claim (and its origin is always a trusted CSRF origin)

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
    redis?: {
      host: string; port: number; username?: string; password?: string; db?: number;
      tls?: boolean | Record<string, unknown>; // true, or ioredis TLS options — use it off the local network
      keepAliveMs?: number;              // default 10_000
    };
  };

  signingKeys: { keys: Record<string, SigningKeyEntry> }; // required — see SigningKeyEntry below

  cookies?: {
    secure?: boolean;    // default: NODE_ENV !== 'development'
    sameSite?: 'lax' | 'strict' | 'none'; // default 'lax'; 'none' requires secure
    domain?: string;     // set → session cookies are __Secure-… and shared with subdomains; unset → host-only (see password-email-auth.md, cookie names)
    trustedOrigins?: string[];   // default [] — your frontends' exact origins (see "CSRF" below)
    refreshTokenInBody?: boolean | 'auto'; // default 'auto' — refresh token in JSON bodies only for non-browser clients (see below)
    sessionPath?: string; // default: `<router mount path>/session`, from the request — pins the refresh cookie's Path (e.g. '/auth/session')
  };

  registration?: {
    acceptMetadata?: boolean; // default false — persist the user-supplied `metadata` from POST /register
  };

  session?: {
    reresolveClaimsOnRefresh?: boolean; // default true (since 0.4.0) — see "Claims are opaque" below
    verifyOnEachRequest?: boolean;      // default true — see middleware.md
    recentAuthMaxAgeSeconds?: number;   // default 900 — how recent a login requireRecentAuth() demands
    absoluteLifetimeSeconds?: number;   // default 7_776_000 (90 days) — a login's refresh-token family ends then, however actively refreshed
    refreshReuseGraceSeconds?: number;  // default 10 — a rotated refresh token replayed within this is only refused; later, it revokes its whole family
  };

  ttls?: Partial<{ /* see table below — all positive integers, in seconds */ }>;

  security: {
    emailHashPepper: string;   // required, ≥ 32 chars — HMAC key for the email blind index, never rotate
    tokenHashSecret: string;   // required, ≥ 32 chars, ≠ emailHashPepper — the per-purpose HMAC keys for opaque tokens at rest are derived from it
    previousTokenHashSecrets?: string[]; // default [] — earlier tokenHashSecret values, newest first: what was hashed under them still verifies
    maxFailedLoginAttempts?: number;  // default 5 wrong passwords per accountLockDurationMs window — then password login (only) is locked
    accountLockDurationMs?: number;   // default 1_800_000 (30 min) — the counting window and the lock's length
    bcryptRounds?: number;            // default 12; integer 10–15 (also the cost of the dummy hash for unknown accounts)
    allowWeakBcryptRounds?: boolean;  // tests only — allows bcryptRounds down to 4
    verificationCodeLockout?: { maxFailedAttempts?: number; windowSeconds?: number; lockSeconds?: number; maxTotalFailedAttempts?: number }; // defaults 5, 86400, 86400 (window and lock raised to at least ttls.emailVerification) — wrong 6-digit codes per verification ticket, and per address for attempts without one; maxTotalFailedAttempts (default 20): wrong codes per address in all (a year-long cap), then only the link works
    passwordChangeLockout?: { maxFailedAttempts?: number; windowSeconds?: number; lockSeconds?: number };   // defaults 5, 3600, 3600 — wrong current passwords at /password/change
  };

  mfa?: {
    issuerLabel?: string;           // default 'App'
    recoveryCodeCount?: number;     // default 10
    enabled?: boolean;              // default true — requires encryptionKey or secretCipher at startup
    encryptionKey?: string | { id: string; key: string }; // exactly the base64 of 32 bytes
    previousEncryptionKeys?: Array<string | { id: string; key: string }>; // default [] — decrypt only
    secretCipher?: SecretCipher;    // custom (e.g. KMS) — takes precedence over encryptionKey
    requireEncrypted?: boolean;     // default: true with encryptionKey or secretCipher, false without — refuse plain-text secrets left from <=0.2.x
    allowPlaintext?: boolean;       // default false — development only
    lockout?: { maxFailedAttempts?: number; windowSeconds?: number; lockSeconds?: number }; // defaults 5, 900, 900
  };
  magicLink?: { allowSignupViaMagicLink?: boolean };                // default true
  webauthn?: {                                                      // no defaults — opt-in
    rpID?: string; rpName?: string; origin?: string | string[];
    allowCredentialsByEmail?: boolean; // default false — passkey-login options ignore `email`
  };
  oauthProviders?: {                                                // see SSO doc
    google?: { clientId: string; clientSecret: string };
    github?: { clientId: string; clientSecret: string };
    microsoft?: { clientId: string; clientSecret: string; tenant?: string /* default 'common' */; trustEmail?: boolean /* default false */ };
    apple?: { clientId: string; teamId: string; keyId: string; privateKeyPem: string };
    linkedin?: { clientId: string; clientSecret: string };
  };
  oidc?: {
    endSessionConfirmationUrl?: string; // default unset — your "sign out?" page; GET /session/end redirects there (https, on the issuer's origin or a trustedOrigins origin)
  };
  clock?: {                          // this server's clock vs the database's — see "Clock skew" below
    maxSkewSeconds?: number;         // default 30 — refuse to start past it; log an error past it later
    warnSkewSeconds?: number;        // default 2 — log a warning past it
    checkIntervalSeconds?: number;   // default 600 (minimum 10) — how often it is re-measured
  };
  oauth2?: {
    requirePkce?: 'all' | 'public';  // default 'all' — PKCE (S256) for every client; 'public' exempts confidential clients
  };
  sso?: {                            // required once any oauthProviders entry has a clientId
    baseCallbackUrl?: string;        // absolute — providers redirect to <base>/sso/<provider>/callback
    allowedRedirectOrigins?: string[]; // exact origins; https, or http only for localhost
    providerTimeoutMs?: number;      // default 10_000 — each provider call
  };
  serviceMesh?: {
    bootstrapSecrets?: Record<string, string>; // preferred — one registration secret per service name (each ≥ 32 chars, ≠ bootstrapSecret)
    bootstrapSecret?: string;        // legacy shared secret (≥ 32 chars) — can only register a name with no key yet, never one in bootstrapSecrets
    allowedServiceNames?: string[];  // restricts which names may register at all
    tokenMode?: 'token' | 'secret' | 'both'; // default 'token'
    ownServiceName?: string;
    sharedSecret?: string;           // ≥ 32 chars
    allowLegacySecretCallers?: boolean; // default false — let requireServiceCallerMiddleware accept shared-secret callers
    rotationGraceSeconds?: number;   // default 3600 — how long a rotated-away (ROTATING) service key still verifies
  };

  rateLimiting?: {
    enabled?: boolean;              // default true
    adapter?: 'memory' | 'redis';   // default 'memory'
    keyPrefix?: string;             // default 'ratelimit:'
    redis?: { host: string; port: number; username?: string; password?: string; db?: number; tls?: boolean | Record<string, unknown> };
    // Each a RateLimitRule { max?, windowSeconds? } merged over its default — see rate-limiter-interface.md
    login?; loginByEmail?; passwordReset?; passwordResetByEmail?; mfaChallenge?; refreshToken?;
    magicLink?; magicLinkByEmail?; register?; emailVerification?; verificationEmailByEmail?;
    webauthnAuthentication?; oauth2Token?; ssoInitiate?; serviceKeyRegistration?;
  };

  webhooks?: {
    endpoints?: Array<{
      url: string;                  // https (http only for localhost)
      secret: string;               // ≥ 16 characters
      events?: string[];            // only these events; default all
      includeCredentials?: boolean; // default false — reset/magic-link tokens and verification codes are stripped
    }>;                              // default [] (disabled)
    maxAttempts?: number;      // default 5
    retryBaseDelayMs?: number; // default 500 (doubles each attempt)
    timeoutMs?: number;        // default 5000
    maxInFlight?: number;      // default 100 — beyond this, events are dropped with a warning
  };

  hooks?: AuthHooks;
  hookTimeoutMs?: number; // default 10_000 — how long a hook is awaited before the request carries on
  logger?: Logger; // default: console-backed logger with { info, warn, error, debug }(obj, msg)
}
```

### `cookies.secure` and local browser testing

`cookies.secure` defaults to `NODE_ENV !== 'development'` — correct fail-safe behavior for
production, but easy to trip over locally: a plain `tsx watch server.ts` / `node server.js` run
leaves `NODE_ENV` unset, so `Secure` cookies get issued over `http://` by default. A real browser
silently refuses to store or send a `Secure` cookie on a non-HTTPS origin — but `curl`, Postman,
and most HTTP clients don't enforce `Secure` at all, so a login flow that looks like it works from
the terminal can still be completely broken in an actual browser with no error surfaced anywhere.
Set `NODE_ENV=development`, or pass `cookies: { secure: false }` explicitly, when testing a
cookie-based (browser) login flow locally. (With Secure the cookies are named `__Host-access_token`,
`__Secure-refresh_token` and `__Host-refresh_binding`; without it, plain `access_token`,
`refresh_token` and `refresh_binding` — see
[cookie names](password-email-auth.md#shared-session-mechanics).) Only relevant if you're relying on
the session cookies at all — an `Authorization: Bearer` client (see
[Register, Login, Refresh, Logout](../examples/register-login-refresh-logout.md)) never touches
cookies and is unaffected.

### CSRF: `cookies.trustedOrigins`

A state-changing request (anything but `GET`/`HEAD`/`OPTIONS`) whose credential is the session
**cookie** must come from a trusted origin, or it's refused with 403 `CSRF_ORIGIN_REJECTED`. The
endpoints that *set* or clear session cookies — `/login`, `/session/refresh`, `/session/logout`, `/mfa/verify`, `/magic-link/verify`,
`/webauthn/authentication/verify`, `/webauthn/mfa/verify` — apply the check to every request,
whatever its credential (login CSRF). `Sec-Fetch-Site:
same-origin` passes; otherwise the `Origin` header must be the issuer's origin or one of
`cookies.trustedOrigins`. A request with neither header (a non-browser client) passes, and
`Authorization: Bearer` requests are never affected. If your frontend lives on another origin than
the IdP (e.g. `https://app.example.com` against `https://auth.example.com`) and uses cookie
sessions — or calls any of those login endpoints from the browser, cookies or not — list it:

```js
cookies: { trustedOrigins: ['https://app.example.com'] } // IDP_COOKIE_TRUSTED_ORIGINS
```

Each entry must be an exact origin — `https://app.example.com`, not `https://app.example.com/` or
`…/login` (checked at startup; such an entry used to silently match nothing).

### `cookies.refreshTokenInBody`

Whether the refresh token is also returned in the JSON body of `/login`, `/session/refresh`, `/mfa/verify`,
`/magic-link/verify`, `/webauthn/authentication/verify` and `/webauthn/mfa/verify` (it is always set
as the httpOnly refresh cookie):

| Value | Refresh token in the JSON body |
|---|---|
| `'auto'` (default since 0.4.0) | Only for non-browser clients. A request carrying an `Origin` or `Sec-Fetch-Site` header (which page script can't remove) gets it only as the cookie, so script on the page — an XSS — never reads it. |
| `true` | Always — for a browser app that keeps the refresh token itself (e.g. cross-site, without cookies). |
| `false` | Never. |

`'auto'` relies on the browser sending `Origin` or `Sec-Fetch-Site` on these POSTs, as all current
browsers do; a very old browser that sends neither is treated as a non-browser client and gets the
token in the body. A browser-only app that must cover such browsers sets `false`.

`IDP_COOKIE_REFRESH_TOKEN_IN_BODY` accepts `auto` or a boolean. **Upgrading from 0.3.x:** the
default was `true`; a browser app that reads `refreshToken` from the JSON body must set `true` (or
rely on the refresh cookie instead).

### Clock skew (`config.clock`)

Revocation ordering uses counters and the database's clock, but expiry doesn't: token `exp`, code
and link lifetimes and lockout windows are compared against the clock of the server checking them.
So each server measures its clock against the database's — `storage.databaseTime()`, the midpoint
of the round trip; the Mongo adapter reads `hello.localTime` — at startup, refusing to start past
`clock.maxSkewSeconds` (default 30) and warning past `warnSkewSeconds` (default 2), then again every
`checkIntervalSeconds` (default 600), logging an error past the maximum (and a warning past the
warning level). Servers measured against the same clock stay within 2 × `maxSkewSeconds` of each
other. Closing the storage stops the periodic check. A storage adapter without `databaseTime()`
boots with a startup warning and no check.

For a health check, `checkClockSkew()` measures it on demand:

```js
import { checkClockSkew } from '@okeav/idp-core';

app.get('/healthz', async (req, res) => {
  const clock = await checkClockSkew(); // { skewMs, ok, level }
  res.status(clock.ok ? 200 : 503).json({ clock });
});
```

`skewMs` is this server's clock minus the database's (`null` with `level: 'unknown'` when the
adapter has no `databaseTime()`); `level` is `'ok'`, `'warn'` (past `warnSkewSeconds`) or `'error'`
(past `maxSkewSeconds`, the only level with `ok: false`). It rejects if the database can't be
reached.

### Rotating `security.tokenHashSecret`

What idp-core stores in place of an opaque value — refresh tokens, authorization codes,
email-verification links and codes, password-reset links, magic links, MFA recovery codes, OAuth2
client secrets — is an HMAC-SHA256 under a key derived from `tokenHashSecret` for that purpose
(HKDF-SHA256, one key per `HASH_PURPOSES` entry in `src/signing/token.service.js`). Nothing is keyed
by the secret itself, and a hash made for one purpose never verifies as another.

To rotate it, set the new value as `tokenHashSecret` and move the old one to the front of
`previousTokenHashSecrets` (env `IDP_PREVIOUS_TOKEN_HASH_SECRETS`, comma-separated, newest first).
New hashes use the current secret; anything hashed under a listed previous secret still verifies.
An OAuth2 client secret that verifies under a previous secret is re-stored under the current one on
that use; nothing else is re-hashed (a refresh token moves to the current secret when it is rotated,
since its successor is new). Entries are checked at startup: ≥ 32 characters, not the current
`tokenHashSecret`, not `emailHashPepper`, no duplicates.

Drop an old secret once nothing hashed under it is still needed:

- **Refresh tokens** — after `session.absoluteLifetimeSeconds` (default 90 days); links,
  verification codes and authorization codes expire much sooner (`ttls`).
- **OAuth2 client secrets** — once every confidential client has authenticated since the rotation
  (or had its secret rotated); a client that hasn't is refused after the drop.
- **MFA recovery codes** — not re-stored on use. Keep the old secret until users have regenerated
  their codes (`POST /me/mfa/recovery-codes`), or accept that unused old codes stop working.

Previous secrets are derived the same way, so this covers values hashed by 0.4.0 or later only:
hashes written by 0.3.x (keyed by the secret itself) don't verify even with that secret listed —
see [Tokens & Signing](tokens-rs256.md#opaque-token-hashing).

A lookup that finds nothing (an unknown or expired token) tries every previous secret in turn, so
keep the list short. `emailHashPepper` is different: it keys the email blind index and can never be
rotated.

### Client IPs and `trust proxy`

Every per-IP rate limit keys on `req.ip` (IPv6 clients by their /64, IPv4-mapped addresses as IPv4 —
see [Rate Limiter Interface](rate-limiter-interface.md#keys)). `req.ip` is only as trustworthy as
Express's `trust proxy` setting. Behind a load balancer or reverse proxy, set it to the number of
proxy hops or the proxies' subnet:

```js
app.set('trust proxy', 1);              // one proxy hop (e.g. a single load balancer)
// app.set('trust proxy', '10.0.0.0/8'); // or the proxies' subnet
```

**Never `true`**: that trusts whatever `X-Forwarded-For` the client sends, so anyone can pick a
fresh IP per request and walk past every per-IP limit. Without a proxy, leave it unset.

### MFA secret encryption (`config.mfa`)

Since 0.3.0 TOTP secrets are encrypted at rest, and because `mfa.enabled` defaults to `true`,
**`initIdentityProvider()` throws unless `mfa.encryptionKey` (or `mfa.secretCipher`) is set**:

```bash
openssl rand -base64 32   # → IDP_MFA_ENCRYPTION_KEY / config.mfa.encryptionKey
```

The key must be exactly the base64 of 32 bytes — trailing garbage is refused (it used to be
ignored). If the deployment doesn't use TOTP at all, set `mfa.enabled: false` instead (no key
needed; `setupMfaHandler`/`confirmMfaHandler` then respond 404 `FEATURE_DISABLED`).
`mfa.allowPlaintext: true` boots without a key for local development only, with a loud warning.

Since 0.4.0 `mfa.requireEncrypted` defaults to `true` whenever `encryptionKey` or `secretCipher` is
set (`false` without one — the `allowPlaintext` development mode), so a plain-text TOTP secret is
refused (500 `MFA_SECRET_NOT_ENCRYPTED`) rather than used — that user can't complete MFA with a TOTP
code or even a recovery code (only a passkey second factor) until it is migrated. If secrets written by ≤ 0.2.x may remain,
run `migrateMfaSecrets()` before upgrading, or set `requireEncrypted: false` explicitly until it has
run. Format, rotation, and migration: [MFA](mfa.md#secret-encryption-at-rest).

### `SigningKeyEntry`

```ts
interface SigningKeyEntry {
  privateKey?: string; // PEM or base64-PEM. Omit on a verify-only key (e.g. RETIRED).
  publicKey: string;   // PEM or base64-PEM.
  status: 'ACTIVE' | 'ROTATING' | 'RETIRED' | 'REVOKED';
}
```

Every key is checked at startup: it must be an RSA key (tokens are RS256) of at least 2048 bits,
both PEMs must parse, a `privateKey` must actually belong to its `publicKey`, and `status` must be
one of the four values. At least one `ACTIVE` or `ROTATING` key must have a `privateKey`.

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
| `refreshToken` | 2,592,000 (30d) — each token; capped by the family's `session.absoluteLifetimeSeconds` |
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
right before token issuance, defaults to `() => ({})`.

Since 0.4.0 `POST /session/refresh` calls it again on every refresh (`session.reresolveClaimsOnRefresh`,
default `true`, with `ctx.method: 'refresh'`), so a demotion or suspension in your app takes effect
at the next access-token rotation. Keep the hook fast. Set it `false` to carry the login-time
`claims` forward verbatim for the whole session family (up to `session.absoluteLifetimeSeconds`).

The `User` record handed to `resolveAuthContext` does carry a generic `metadata` object, but no
route lets a user edit it, and `POST /register` writes it only with `registration.acceptMetadata:
true` — in which case it's attacker-controlled and must never hold a role or tenant. For your own
app data (a `role`, an RBAC `capabilities` array, ...) see
[Storing App-Specific User Data](../examples/consumer-managed-app-data.md).

## What this package deliberately does not do

- No RBAC decisioning — no scope catalogue, wildcard permission matcher, or `requirePermission()`.
- No message bus, SMTP, or push integration — wire your own inside the hooks (see
  [Event hooks](#event-hooks-confighooks) below).
- No secrets-vault client — resolve config values before calling `initIdentityProvider()`.
- No QR-code rendering for MFA — `setupMfaHandler` returns the raw `otpauth://` URI.

## Event hooks (`config.hooks`)

All hooks are optional and default to no-ops. Every hook in the table below **except
`resolveAuthContext`** is invoked through a safety net (`safeInvokeHook` in `src/hooks/index.js`):
a hook that throws is logged (`logger.warn`, with the error's `name` and `message` only — a
consumer's error can embed the token being mailed) and swallowed, never breaking the request it's
attached to, and a hook is awaited for at most `hookTimeoutMs` (default 10 s) — after that the
request carries on and the hook keeps running in the background, so a hung mail API can't stall a
login.

On the endpoints that must not reveal whether an account exists — register, resend verification,
forgot password, magic-link request — the email hooks (`onVerificationEmailRequested`,
`onPasswordResetRequested`, `onMagicLinkRequested`) and their audit events are **started but not
awaited**, since waiting for an email to be sent made those responses measurably slower for real
accounts. Their first synchronous step still runs before the response — except on resend
verification and forgot password, which answer before looking the address up and do the lookup,
writes and hook afterwards. In serverless runtimes, make
those hooks hand off quickly (enqueue rather than send inline).

**`resolveAuthContext` is the one exception — it is not wrapped in that safety net.** It's called
directly (`await hooks.resolveAuthContext(user, ctx)`, no try/catch, no timeout) from every login
path that mints a session, and from `/session/refresh` while `reresolveClaimsOnRefresh` is on. A
throwing/rejecting `resolveAuthContext` propagates and turns that request into an error response
instead of being swallowed. It also isn't in `defaultHooks()` at all — omitting it entirely is
equivalent to it resolving `{}` (no claims), not to a registered no-op.

| Hook | Fires on | Payload |
|---|---|---|
| `onAuditLog(event)` | Every audit-worthy action | `{ action, ...eventFields, timestamp }` — `action` values include `REGISTERED`, `REGISTRATION_REPEATED` (a still-pending address registered again), `EMAIL_VERIFIED`, `EMAIL_VERIFICATION_LOCKED`, `VERIFICATION_TOKEN_REGENERATED`, `LOGIN`, `LOGOUT`, `LOGOUT_ALL`, `TOKEN_REFRESHED`, `REFRESH_TOKEN_REUSE_DETECTED`, `PASSWORD_RESET`, `PASSWORD_CHANGED`, `PASSWORD_CHANGE_LOCKED`, `ACCOUNT_LOCKED` (password login locked by failed attempts), `PROFILE_UPDATED`, `ACCOUNT_DELETED`, `SESSION_REVOKED`, `SESSIONS_REVOKED_ALL`, `MAGIC_LINK_REQUESTED`, `MAGIC_LINK_LOGIN`, `MAGIC_LINK_MFA_REQUIRED`, `WEBAUTHN_CREDENTIAL_REGISTERED`, `WEBAUTHN_CREDENTIAL_DELETED`, `WEBAUTHN_LOGIN`, `MFA_SETUP_INITIATED`, `MFA_ENABLED`, `MFA_DISABLED`, `MFA_RECOVERY_CODES_REGENERATED`, `MFA_VERIFIED`, `MFA_LOCKED` (see [MFA](mfa.md#per-account-lockout)), `SSO_INITIATED`, `SSO_LOGIN`, `SSO_REGISTERED`, `SSO_PROVIDER_LINKED`, `SSO_PENDING_ACCOUNT_CLAIMED`, `SSO_MFA_REQUIRED`, `OAUTH2_AUTHORIZE`, `OAUTH2_CONSENT_GRANTED`, `OAUTH2_CONSENT_DENIED`, `OAUTH2_TOKEN_ISSUED`, `OAUTH2_TOKEN_REVOKED`, `OAUTH2_CODE_REUSE_DETECTED`, `CONSENT_REVOKED`, `END_SESSION`, the `OAUTH_CLIENT_*` admin actions, and `SERVICE_KEY_REGISTERED`/`SERVICE_KEY_REGISTRATION_REFUSED` (`reason` e.g. `name_has_own_secret`, `name_taken`, `key_revoked`)/`SERVICE_KEY_REVOKED` |
| `onVerificationEmailRequested` | Registration (including re-registering a still-pending address) and resend-verification — not awaited | `{ email, firstName?, lastName?, verificationToken, verificationCode }` — **`verificationCode` is `null`** once the address has had 3 codes in the code lifetime: send the link only (see [Password & Email Auth](password-email-auth.md#codes-per-address)) |
| `onPasswordResetRequested` | Forgot-password — not awaited | `{ email, resetToken, firstName?, lastName? }` |
| `onPasswordChanged` | Password change/reset completed | `{ userId, email, firstName, lastName, locale, when, deviceInfo, ipAddress }` |
| `onSuspiciousActivityDetected` | Password login locked after too many failed logins (fires once, when the lock starts) | `{ userId, email, firstName, lastName, locale, when, failedAttempts, unlocksAt }` |
| `onNewDeviceLogin` | Login from a browser/OS combination not seen before for this user | `{ userId, email, firstName, lastName, locale, when, deviceInfo, ipAddress }` |
| `onMagicLinkRequested` | Magic-link login requested — not awaited | `{ email, magicLinkToken, firstName?, lastName?, isNewUser }` |
| `resolveAuthContext(user, ctx)` | Password login, MFA-verify, SSO callback, magic-link verify, WebAuthn login, and `/session/refresh` (while `reresolveClaimsOnRefresh`) | Returns `{ claims }`; `ctx = { isNewUser, isNewLink?, method?, provider?, extra? }`. `method` is `password`, `mfa`, `magic_link`, `webauthn`, `webauthn-mfa` or `refresh`; SSO passes `provider` instead. SSO's `extra` holds up to 10 short string query params from the initiating request — attacker-controllable, never trust them |

This package never talks to a message bus, SMTP server, or push provider directly — wire your own
inside these hooks. See [Outbound Webhooks](webhooks.md) for the additive HTTP-delivery mechanism
built on top of these same hooks (credential fields are stripped from deliveries unless the
endpoint sets `includeCredentials`).

## Related

- [Errors](errors.md) — every request-time error is an `IdpError`; mount `idpErrorHandler()`.
- [Tokens & Signing (RS256)](tokens-rs256.md)
- [Repository Adapters](repository-adapters.md) — the `storage.factory` extension point.
- [Cache Interface](cache-interface.md), [Rate Limiter Interface](rate-limiter-interface.md)
- [Outbound Webhooks](webhooks.md)
- [Storing App-Specific User Data](../examples/consumer-managed-app-data.md) — the
  `resolveAuthContext` pattern for role/capability/profile fields idp-core doesn't model itself.
