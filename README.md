# @okeav/idp-core

A standalone, pluggable identity provider for Node.js/TypeScript backends — OAuth2/OIDC authorization server, password + MFA + WebAuthn/passkeys + magic-link + social login, session management, rate limiting, outbound webhooks, and service-to-service JWKS trust. Bring your own MongoDB; everything else (Redis, RabbitMQ, Elasticsearch, a secrets vault) is optional or entirely absent.

Extracted from and generalized out of Okeav's internal `auth-service`. Business-specific concepts (account types, roles, capability scopes) are deliberately **not** part of this package — it issues and verifies opaque `claims` on your behalf without ever interpreting them. Bring your own RBAC layer.

## Install

Requires Node >=20 (needed by `@simplewebauthn/server`, a direct dependency used for the WebAuthn/passkey endpoints — installed automatically, no separate `npm install` step).

```bash
npm install @okeav/idp-core
npm install express cookie-parser   # peer dependencies you likely already have (express ^4.21.2 || ^5.1.0)
npm install ioredis                 # only if you use the Redis cache adapter (also shared by the Redis rate-limiter adapter)
```

Run `npm audit` in your app too: `proxy-addr` ≤ 2.0.7 (IP spoofing through `trust proxy` subnets), `body-parser` and `qs` have had advisories, all fixed by updating within Express's own ranges.

## Local development

```bash
docker compose up -d   # single-node Mongo replica set (rs.initiate() already run) + Redis, both bound to 127.0.0.1 with no auth
npm test                # runs the critical-path suite against an in-memory Mongo replica set
```

See `examples/express-quickstart/` for a complete, copy-pasteable server wired against the compose stack above — start there if you want to see the package running before reading the config reference below.

## Quick start

```js
import express from 'express';
import { initIdentityProvider, buildRouter, cookieParser, configFromEnv, idpErrorHandler } from '@okeav/idp-core';

await initIdentityProvider({
  ...configFromEnv(), // reads the IDP_* env vars documented in .env.example — including IDP_MFA_ENCRYPTION_KEY
  hooks: {
    // Not awaited by /register (so its timing can't reveal which addresses exist) — enqueue, don't block.
    onVerificationEmailRequested: async ({ email, verificationCode }) => {
      await sendEmail(email, `Your verification code is ${verificationCode}`);
    },
    resolveAuthContext: async (user) => ({ claims: { role: 'member' } }),
  },
});

const app = express();
app.set('trust proxy', 1);  // behind one proxy hop — set your hop count or subnet, never `true`
app.use(cookieParser());    // before the router: cookie sessions and the SSO binding cookie need it
app.use(express.json());
app.use('/auth', buildRouter());
app.use(idpErrorHandler()); // after the router — see "Error handling" below

app.listen(3000);
```

`buildRouter()` mounts every surface by default except OAuth2 client administration
(`/oauth2/clients*`), which it mounts only behind your own admin middleware:
`buildRouter({ clientManagement: { middleware: [requireAdmin] } })`. `features: { sso: false, ... }`
leaves a surface (`magicLink`, `webauthn`, `sso`, `oauth2`, `oidc`, `serviceMesh`) unmounted. Every
response from the router carries `Cache-Control: no-store`, except the public discovery and key
documents, which set their own public cache lifetimes (JWKS and `/keys/:kid` 300 s, the services
JWKS 60 s, discovery `ttls.discoveryCache`). See `docs/api/router-and-schemas.md`.

Prefer wiring routes yourself? Every handler in `buildRouter()` is also a named export — `import { loginHandler } from '@okeav/idp-core'` — so you can mount them on your own router with your own paths, rate limiters, and middleware order.

## Upgrading from 0.3.x

0.4.0 is a security release from a full audit of 0.3.0, and it is **breaking**. `CHANGELOG.md` has every item with its upgrade note; the ones most deployments must act on:

1. **Startup validation.** `initIdentityProvider()` now refuses `emailHashPepper`/`tokenHashSecret` under 32 characters, `bcryptRounds` outside 10–15, non-RSA or < 2048-bit signing keys (or a private key that doesn't match its public key), webhook endpoints that aren't `https` or whose secret is under 16 characters, and — with any SSO provider configured — a missing `sso.allowedRedirectOrigins` or `sso.baseCallbackUrl`. `configFromEnv()` parses strictly: booleans accept true/false, 1/0, yes/no, on/off; anything unrecognised fails startup.
2. **Access tokens are first-party only by default.** `authContextMiddleware`/`verifyAccessToken` accept only tokens this IdP issued for itself. A resource server that accepts OAuth2 tokens opts in with `authContextMiddleware({ accept: ['oauth2-user'] })` and checks `req.auth.scopes`; a first-party token minted with a custom `audience` needs `authContextMiddleware({ audience })`.
3. **Errors.** Mount `idpErrorHandler()` after the router instead of a handler that echoes `err.message` (the one this README used to show leaked database and body-parser internals).
4. **CSRF.** Cookie-authenticated state-changing requests must come from the issuer's origin or `cookies.trustedOrigins` (`IDP_COOKIE_TRUSTED_ORIGINS`) — list your frontends' origins.
5. **Frontend flows.** Magic-link verify and the SSO callback now stop at the MFA challenge for MFA accounts; OAuth2 consent pages post the `consent_challenge` they received; every OAuth2 client sends PKCE (`S256`); `POST /me/mfa/recovery-codes` takes `{ password, code }`; passkey registration, MFA enrolment and account deletion answer 401 `REAUTHENTICATION_REQUIRED` unless the user logged in within the last 15 minutes.
6. **Claims are re-resolved on refresh** (`session.reresolveClaimsOnRefresh` now defaults to `true`) — keep `resolveAuthContext` fast, or set it `false`.
7. **Webhooks** no longer carry reset tokens, magic-link tokens or verification codes unless the endpoint sets `includeCredentials: true` — set it on the endpoint that sends your emails.
8. **SSO** with Microsoft on the `common` authority can no longer create or link accounts by email; pin `tenant`, or set `trustEmail: true` knowingly.
9. **Service mesh** defaults to `tokenMode: 'token'`; prefer per-service `serviceMesh.bootstrapSecrets`.
10. **Custom storage adapters** should persist the new session fields (`kind`, `authTime`, `familyId`, `familyCreatedAt`) and add the new atomic methods — see "Storage" below. Custom cache adapters must add an atomic `take()`.

## Upgrading from 0.2.x

0.3.0 was a security release with three changes that need action or a decision:

1. **OAuth2 client management is no longer mounted by default.** `buildRouter()` used to mount
   `/oauth2/clients*` unauthenticated; now those paths 404 unless you pass
   `clientManagement: { middleware: [yourAdminAuth] }`. If you administer clients over HTTP, pass
   it; if you had a workaround that 404'd `/oauth2/clients*`, remove it.
2. **TOTP secrets are encrypted at rest, and a key is required.** Set `mfa.encryptionKey`
   (`IDP_MFA_ENCRYPTION_KEY`, `openssl rand -base64 32`) — or `mfa.enabled: false` if you don't use
   TOTP — or `initIdentityProvider()` throws. Deploy; run `migrateMfaSecrets()` once to encrypt
   existing secrets (they're also re-encrypted lazily on each user's next MFA verify); then set
   `mfa.requireEncrypted: true`. See `docs/api/mfa.md`.
3. **Access tokens die on logout-all / password reset.** `session.verifyOnEachRequest` (default
   `true`) makes `authContextMiddleware` check the token's session row on every request, so
   revocations take effect on every instance immediately. Budget one indexed storage read per
   authenticated request, or set it `false` to keep 0.2.x behaviour (revoked users' access tokens
   live until expiry, up to 1 hour by default). See `docs/api/middleware.md`.

Also new in 0.3.0: a per-account MFA lockout (`mfa.lockout`, 5 failures → 15-minute lock, returning
429 `MFA_LOCKED`), and rate limiting that fails closed on credential checks (see "Rate limiting"
below). Custom storage adapters keep working but should add `sessionRepository.findByJti` and
`attemptCounterRepository` (see "Storage").

## Configuration

See `.env.example` for the full list of environment variables and `types/index.d.ts` for the `IdpConfig` shape (`docs/api/bootstrap-config.md` documents both, with every default and startup check). Required fields:

- `issuer` — this IDP's URL, used as the JWT `iss` claim.
- `mongo.uri` (or `mongo.connection` — an existing Mongoose connection).
- `signingKeys.keys` — at least one `ACTIVE` RS256 keypair (PEM or base64 PEM), RSA ≥ 2048 bits.
- `security.emailHashPepper` — HMAC key for the email blind index; random, at least 32 characters, never rotated.
- `security.tokenHashSecret` — HMAC key for hashing opaque refresh/reset/verification tokens at rest; random, at least 32 characters.
- `mfa.encryptionKey` — exactly the base64 of 32 bytes (`openssl rand -base64 32`); encrypts TOTP secrets at rest (AES-256-GCM). Required while `mfa.enabled` (default `true`); set `mfa.enabled: false` instead if you don't use TOTP. Rotation and KMS-backed ciphers: `docs/api/mfa.md`.
- `sso.allowedRedirectOrigins` and `sso.baseCallbackUrl` — only once any `oauthProviders` entry is configured.

Everything else has a sensible default. RBAC-shaped config (roles, scopes, capabilities) doesn't exist in this schema on purpose — see "Claims are opaque" below.

**`trust proxy`.** Per-IP rate limits key on `req.ip` (IPv6 clients by their /64). Behind a load balancer or reverse proxy, set Express's `trust proxy` to the hop count or the proxies' subnet — never `true`, which lets any client pick its own IP through `X-Forwarded-For`.

### Cache adapter

`config.cache.adapter` is `'memory'` (default) or `'redis'`.

- **memory** — zero config, but single-process only. State (revocation cache, SSO CSRF state, WebAuthn and OAuth2 consent challenges) is lost on restart and not shared across instances. Capped at 100k entries. Fine for local dev or a genuinely single-instance deployment; wrong for anything horizontally scaled.
- **redis** — set `config.cache.adapter = 'redis'` and `config.cache.redis = { host, port, username?, password?, tls? }` (`tls: true` for managed Redis or anything off the local network). Requires `ioredis` as a peer dependency; it's only `import()`-ed when this adapter is actually selected.

A custom cache adapter must implement an atomic `take(key)` (get-and-delete) alongside `get`/`set`/`del`/`expire` — it's what keeps single-use challenges single-use. See `docs/api/cache-interface.md`.

**Revocation checks fail closed regardless of adapter.** By default (`config.session.verifyOnEachRequest: true`) `authContextMiddleware` looks up the access token's session row by `jti` on every request — one indexed read — and rejects it (401 `TOKEN_REVOKED`) if the session is gone, revoked, or expired, so logout-all, password reset, and session revocation take effect on every instance at once. The cache is only a fast path in front of that: a cached revocation short-circuits, a cache error is logged and storage decides, and a storage error rejects with 503 `SESSION_STORE_UNAVAILABLE`. With `verifyOnEachRequest: false` (0.2.x behaviour) only the cache is checked: a cache *error* rejects with 503 `CACHE_UNAVAILABLE`, a *miss* means "not revoked", and access tokens survive logout-all and password reset/change until they expire (the cache only records single-session logouts/revocations, on the instance that handled them).

### Access tokens and `authContextMiddleware`

Access tokens are one of three kinds: `first-party` (issued by this IdP's own login flows, `aud` = the issuer), `oauth2-user` (issued to a third-party OAuth2 client for a user) and `oauth2-client` (`client_credentials`, no user). `authContextMiddleware()` and `verifyAccessToken()` accept only `first-party` by default — a token a user granted some relying party is never a credential for the IdP's own routes. A resource server that accepts OAuth2 tokens opts in and checks scopes itself:

```js
app.get('/api/orders', authContextMiddleware({ accept: ['oauth2-user'] }), (req, res) => {
  if (!req.auth.scopes?.includes('orders:read')) return res.status(403).end();
  // req.auth = { userId, email, claims, tokenKind, clientId, scopes, tokenMeta: { issuedAt, expiresAt, jti, authTime } }
});
```

`req.auth.userId` is `undefined` for `oauth2-client` tokens. `verifyAccessToken()` checks signature, issuer, expiry, type and kind/audience — **not** revocation; use `authContextMiddleware` where a logged-out session must stop working. `requireRecentAuth()` (mount after `authContextMiddleware`) answers 401 `REAUTHENTICATION_REQUIRED` unless the user actually logged in within `session.recentAuthMaxAgeSeconds` (default 15 minutes); the router uses it for passkey registration and deletion, MFA enrolment and account deletion. See `docs/api/middleware.md`.

**Cookie sessions and CSRF.** A state-changing request authenticated by a cookie (the session cookie, or the refresh cookie at `/refresh` and `/logout`) must come from the issuer's origin or one of `cookies.trustedOrigins`, or it gets 403 `CSRF_ORIGIN_REJECTED`; `Authorization: Bearer` requests and non-browser clients are unaffected. For browser-only apps, `cookies.refreshTokenInBody: false` keeps the refresh token out of JSON responses entirely.

### Sessions

Each login starts a refresh-token *family*. `/refresh` rotates the token; a rotated token presented again after `session.refreshReuseGraceSeconds` (default 10 s — two tabs refreshing at once) revokes the whole family and emits `REFRESH_TOKEN_REUSE_DETECTED`. A family ends `session.absoluteLifetimeSeconds` (default 90 days) after its login however actively it's refreshed. First-party and OAuth2 refresh tokens are not interchangeable: `/refresh` accepts only first-party ones, the OAuth2 `refresh_token` grant only those issued to the calling client. Enabling MFA signs out the account's other sessions. See `docs/api/password-email-auth.md`.

### Claims are opaque

`issueAccessToken({ sub, email, claims })` — `claims` is whatever object you pass. It comes back untouched as `req.auth.claims` after `authContextMiddleware`. This package never validates its shape, and ships no scope-matching or permission-checking logic — that's your application's job (or a separate RBAC package).

For login flows that mint a session on your behalf (password login, MFA-verify, SSO callback, magic-link verify, WebAuthn login), configure `hooks.resolveAuthContext(user, ctx)` to build that `claims` object — it's called right before the token is issued and defaults to `() => ({})` if you don't supply one.

Since 0.4.0 `POST /refresh` calls `resolveAuthContext(user, { isNewUser: false, method: 'refresh' })` again on every refresh (`config.session.reresolveClaimsOnRefresh`, default `true`), so a role change or suspension in your app takes effect within one access-token TTL. Keep the hook fast — it runs on every refresh. Set `reresolveClaimsOnRefresh: false` to carry the login-time `claims` forward instead; they then stay frozen for the whole session family (up to `session.absoluteLifetimeSeconds`).

The user record has a `metadata` object, but `POST /register` writes it only with `registration.acceptMetadata: true` — and then it's attacker-controlled, so never derive a role or tenant from it. Keep app data in your own collection (`docs/examples/consumer-managed-app-data.md`).

### Event hooks

All hooks are optional, default to no-ops, and are never thrown — a hook that throws is logged and swallowed, never breaks the request it's attached to. Each is awaited for at most `hookTimeoutMs` (default 10 s); after that the request carries on and the hook keeps running. On the endpoints that must not reveal whether an account exists (register, resend verification, forgot password, magic-link request) the email hooks are started but not awaited — in serverless runtimes, make them hand off quickly (enqueue rather than send inline).

| Hook | Fires on |
|---|---|
| `onAuditLog(event)` | Every audit-worthy action (login, logout, password change, MFA changes, OAuth2 grants, admin actions, SSO events, refresh-token reuse, etc.) — `event.action` identifies which one. |
| `onVerificationEmailRequested` | Registration (including re-registering a still-pending address) and resend-verification. |
| `onPasswordResetRequested` | Forgot-password. |
| `onPasswordChanged` | Password change/reset completed. |
| `onSuspiciousActivityDetected` | Account locked after too many failed logins. |
| `onNewDeviceLogin` | Login from a browser/OS combination not seen before for this user. |
| `onMagicLinkRequested` | Magic-link login requested — carries the raw token to embed in the emailed link. |
| `resolveAuthContext(user, ctx)` | Password login, MFA-verify, SSO callback, magic-link verify, WebAuthn login — builds the access token's `claims`. Also called on `/refresh` while `config.session.reresolveClaimsOnRefresh` is `true` (the default). Not wrapped: a throw fails the login. |

This package never talks to a message bus, SMTP server, or push provider directly — wire your own inside these hooks.

### Rate limiting

Request-rate limiting is enabled by default (`config.rateLimiting.enabled = true`) and is a distinct concern from `security.maxFailedLoginAttempts` (which locks one account after N wrong passwords). Rate limiting instead throttles the *rate* of requests to the sensitive endpoints within a fixed window, regardless of whether individual requests succeed:

| Rule | Endpoint | Default limit |
|---|---|---|
| `login` | Login, per IP | 10 / 15 min |
| `loginByEmail` | Login, per address | 5 / 15 min |
| `passwordReset` | Password reset request, per IP | 3 / hour |
| `passwordResetByEmail` | Password reset request, per address | 3 / hour |
| `mfaChallenge` | MFA challenge verification, per IP | 5 / 15 min |
| `refreshToken` | Refresh token, per IP | 30 / min |
| `magicLink` | Magic-link request, per IP | 3 / hour |
| `magicLinkByEmail` | Magic-link request, per address | 3 / hour |
| `register` | Register and resend-verification, per IP | 10 / hour |
| `emailVerification` | Verify-email, per IP | 20 / 15 min |
| `verificationEmailByEmail` | Verification emails sent to one address | 3 / hour |
| `webauthnAuthentication` | Passkey login options + verify, per IP | 60 / 5 min |
| `oauth2Token` | `/oauth2/token`, `/token/revoke`, `/token/introspect`, per IP | 120 / min |
| `ssoInitiate` | `GET /sso/:provider`, per IP | 30 / 5 min |
| `serviceKeyRegistration` | `POST /internal/service-keys`, per IP | 20 / 15 min |

The MFA challenge limit covers both `/mfa/verify` and `/webauthn/mfa/verify`. Separately — and regardless of `rateLimiting.enabled` — per-**account** lockouts are counted in storage, so they hold across instances and IPs: the MFA lockout (`config.mfa.lockout`, default 5 failed second-factor attempts in 15 min → locked for 15 min, 429 `MFA_LOCKED`) and the email-verification lockout (`security.verificationCodeLockout`, default 5 wrong codes per hour → outstanding codes deleted, 429 `VERIFICATION_LOCKED`).

Override any rule under `config.rateLimiting.<rule>` — each takes `{ max, windowSeconds }` (positive integers). Set `config.rateLimiting.enabled = false` to disable entirely if you already rate-limit at a gateway/CDN layer (e.g. Cloudflare, an API gateway) covering every one of these endpoints — running it twice is redundant, not harmful, but the extra storage round-trip on every request is pure overhead if a layer in front of this service already enforces it.

Per-IP keys collapse IPv6 addresses to their /64; per-address keys use the email's keyed hash, so Redis and logs never hold email addresses. Uses the same adapter pattern as the cache layer: `config.rateLimiting.adapter` is `'memory'` (default, single-process, capped at 500k keys — when full, new keys are refused and fail closed) or `'redis'` (shares the cache adapter's Redis connection automatically if `config.cache.adapter` is also `'redis'`, otherwise set `config.rateLimiting.redis` separately — startup fails rather than connecting to an unconfigured localhost).

**Backend errors fail closed everywhere except refresh.** If the rate limiter's backend errors (Redis down, timeout), every limited request is rejected with 503 `RATE_LIMITER_UNAVAILABLE` — an attacker who can knock the limiter over must not get unlimited guesses. Refresh fails open: the error is logged and the request proceeds.

### Magic link (passwordless email login)

`requestMagicLinkHandler` / `verifyMagicLinkHandler` — a single-use, time-limited (`ttls.magicLink`, default 15 min) email link, built on the same `VerificationTokenRepository` as email verification and password reset (no separate storage). Requesting a link invalidates earlier ones, and requests are limited per IP and per address. Requesting a link for an unknown email creates a new `PENDING_VERIFICATION` user and fires `onMagicLinkRequested` with the raw token to embed in your emailed link — gated by `config.magicLink.allowSignupViaMagicLink` (default `true`; set `false` for invite-only apps where an unrecognized email should silently no-op instead of signing someone up). Activating an account by magic link discards any password or MFA state set before the address was proven.

Verifying the token goes through the exact same `resolveAuthContext` → session-issuance path as every other login method — there's no separate, weaker code path for magic-link sessions. For an account with MFA enabled, verify answers `{ mfaRequired: true, mfaChallengeToken, expiresIn }` instead of a session, exactly like password login; complete it at `/mfa/verify` or `/webauthn/mfa/verify`.

### WebAuthn / passkeys

Eight endpoints across four flows, all opt-in behind `config.webauthn.{rpID, rpName, origin}` (validated lazily on first use, not at `initIdentityProvider()` startup, so consumers who don't use passkeys never need to configure it). `rpID` must be the **frontend's** registrable domain — not necessarily this API's own hostname if the API lives on a subdomain.

| Flow | Endpoints | Auth required? |
|---|---|---|
| Register a passkey on an existing account | `generateRegistrationOptionsHandler`, `verifyRegistrationHandler` | Yes, and a recent login (`requireRecentAuth`) |
| Manage passkeys (`GET /me/passkeys`, `DELETE /me/passkeys/:credentialId`) | `listPasskeysHandler`, `deletePasskeyHandler` | Yes; delete also needs a recent login |
| Primary passwordless login | `generateAuthenticationOptionsHandler`, `verifyAuthenticationHandler` | No (rate limited per IP) |
| Passkey as an MFA second factor (alternative to TOTP) | `generateMfaWebauthnChallengeOptionsHandler`, `verifyMfaWebauthnChallengeHandler` | No (gated by a valid `mfaChallengeToken` instead) |

Primary login uses usernameless/discoverable credentials: `email` in the options request is ignored unless `config.webauthn.allowCredentialsByEmail: true` (listing an address's credential ids would reveal whether it has an account; with the flag on, unknown addresses get a stable decoy id). Primary login and registration require user verification; the MFA variant doesn't. Both the primary-login and MFA-second-factor verify handlers resolve through the same `resolveAuthContext` → session-issuance path as password/SSO/magic-link login. The MFA path additionally checks server-side that the verified credential actually belongs to the challenged user, and a discoverable assertion's `userHandle` must name the credential's owner.

Credentials are stored via the `CredentialRepository` interface (`src/storage/interfaces.js`) alongside the other seven — see "Storage" below.

### Outbound webhooks

Additive to the in-process hooks above — set `config.webhooks.endpoints = [{ url, secret, events?, includeCredentials? }, ...]` and every `onAuditLog`/named hook event *also* gets POSTed as a signed JSON payload (`resolveAuthContext` is excluded, since it's a data-returning callback rather than a one-way event). Leave `endpoints` empty (the default) to disable entirely. Each `url` must be `https` (`http` only for localhost) and each `secret` at least 16 characters — both checked at startup. `events` limits which events an endpoint receives.

**Credentials are stripped by default.** The `resetToken`, `magicLinkToken`, `verificationToken` and `verificationCode` fields are removed from deliveries unless the endpoint sets `includeCredentials: true` — set it only on the endpoint that actually sends those emails, since anyone with access to a receiver (or its logs) could otherwise take over accounts.

Each delivery is a fire-and-forget background operation — a webhook endpoint being slow, erroring, or completely unreachable never blocks or fails the auth request that triggered it, and webhooks are sent even when the in-process hook throws. Failed deliveries retry with exponential backoff (`config.webhooks.maxAttempts`, default 5; `config.webhooks.retryBaseDelayMs`, default 500ms, doubling each attempt) before being logged and dropped. Redirects are not followed. At most `config.webhooks.maxInFlight` (default 100) deliveries run at once; beyond that, events are dropped with a warning.

Request body:

```json
{ "id": "6f1c…", "event": "LOGIN", "payload": { "userId": "...", "email": "..." }, "timestamp": "2026-01-01T00:00:00.000Z" }
```

Headers:

- `X-Idp-Event` — the event name (an `onAuditLog` action like `LOGIN`/`REGISTERED`/`PASSWORD_CHANGED`, or a named-hook event like `onMagicLinkRequested`).
- `X-Idp-Delivery` — the delivery id, also in the signed body as `id`. De-duplicate on the body's `id` (the header isn't signed).
- `X-Idp-Signature` — `t=<unix seconds>,v1=<hex HMAC-SHA256>`, computed over `` `${t}.${rawBody}` `` with your configured `secret` (Stripe-style signing).

Verify it on your receiving end with the exported `verifyWebhookSignature(secret, rawBody, signatureHeader)` helper — `rawBody` must be the exact, unparsed request body bytes/string (verify before you `JSON.parse`). During a secret rotation, pass an array of secrets (current and previous).

### Service-to-service JWKS trust

A differentiator kept from the source this was extracted from: any number of your own backend services can register an S2S signing keypair with this IDP (`initServiceIdentity`) and mint short-lived RS256 tokens to call each other (`mintServiceToken`), verified either in-process (`serviceContextMiddleware`, if the verifying service also runs this package) or over HTTP against `/.well-known/services-jwks.json` (`verifyServiceTokenRemote`, for services that don't).

Give each service its own registration credential with `serviceMesh.bootstrapSecrets: { billing: '<secret>', ... }` — it covers only that service's name and lets it rotate its key. The legacy shared `bootstrapSecret` can only register a name that has no key yet (otherwise 409 `SERVICE_NAME_TAKEN`). `serviceMesh.tokenMode` defaults to `'token'`; `requireServiceCallerMiddleware` refuses shared-secret callers unless `serviceMesh.allowLegacySecretCallers: true`. Service tokens without `exp`, living over 5 minutes, or with `iat` in the future are refused, and `revokeServiceKey(kid)` withdraws a key. See `docs/api/service-mesh.md`.

### SSO / social login

Google, GitHub, Microsoft (Entra ID — defaults to the `common` multitenant endpoint, supporting both work/school and personal Microsoft accounts), Apple, and LinkedIn. Configure whichever you use under `config.oauthProviders`, together with the required `config.sso.allowedRedirectOrigins` (exact origins the browser may be sent back to — `https`, or `http` only for localhost) and an absolute `config.sso.baseCallbackUrl`. Mount `cookie-parser` before the router: `GET /sso/:provider` sets a per-attempt binding cookie the callback requires (login-CSRF protection). Google, Microsoft and GitHub use PKCE; Apple's `id_token` must carry this login's nonce. Provider calls time out after `sso.providerTimeoutMs` (default 10 s).

The callback is a **single step** — it resolves the identity, calls `hooks.resolveAuthContext`, and mints the full session directly. (An earlier two-step "exchange token" design existed in the source this was extracted from, purely because identity resolution and role/permission resolution lived in two different internal services there — not for any redirect-URI or CSRF-security reason. If you need that same split, implement it inside your own `resolveAuthContext`.) For an account with MFA enabled it instead redirects to `redirect_uri` with `#mfa_required=1&mfa_challenge_token=…&expires_in=…` in the fragment and sets no cookies — your frontend completes the challenge.

An account is created or linked by email only when the provider vouches for the address: Google, Apple and LinkedIn must assert `email_verified`, GitHub uses only the account's primary verified address, and Microsoft's address is trusted only when `oauthProviders.microsoft.tenant` names a single tenant (or with an explicit `trustEmail: true`). Otherwise the callback redirects with `error=email_not_verified`; a provider-side error redirects with `error=provider_error`. See `docs/api/sso-social-login.md`.

### Error handling

Every error this package throws on purpose is an `IdpError` (`{ code, httpStatus, status, statusCode, expose, message, cause? }`) passed to `next(err)`. The package never shapes an HTTP response body itself — mount the exported `idpErrorHandler()` after the router:

```js
app.use('/auth', buildRouter());
app.use(idpErrorHandler({ logger })); // logger optional
```

It answers an `IdpError` below 500 with `{ error: code, message }`, malformed or oversized bodies with fixed 400/413 messages, and everything else with a bare 500 `{ error: 'INTERNAL_ERROR' }` (logged). If you write your own handler for a different envelope, keep the same rule — never echo the message of a non-`IdpError` (database and body-parser errors carry collection names, values and request bodies). See `ERROR_CODES` and `docs/api/errors.md` for the catalogue of codes you might see.

## Storage

MongoDB is the only concrete storage adapter shipped in this package, behind eight repository interfaces (`UserRepository`, `SessionRepository`, `AuthorizationCodeRepository`, `ConsentRepository`, `OAuthClientRepository`, `VerificationTokenRepository`, `ServiceKeyRepository`, `CredentialRepository` — documented in `src/storage/interfaces.js`). Other adapters (Postgres, DynamoDB, ...) implement the same eight interfaces and plug in through `config.storage.factory`; nothing above the storage layer needs to change.

Optional additions, each with a startup warning and a weaker fallback when missing:

- 0.3.0: `SessionRepository.findByJti` (the per-request session check) and an `AttemptCounterRepository` (the MFA lockout counter; Mongo stores it in the `IdpAttemptCounter` collection). Without them, access tokens survive logout-all and password reset until they expire, and the lockout is counted per instance. `@okeav/idp-core-postgres` 0.2.0 implements both.
- 0.4.0: `UserRepository.claimTotpStep` and `consumeRecoveryCode` (atomic TOTP-replay and recovery-code checks), `SessionRepository.revokeFamily` and `revokeForClient` (refresh-token reuse detection; consent revocation and client deactivation), and `AuthorizationCodeRepository.findUsedByCodeHash` (authorization-code reuse). `revokeAllForUser` takes `{ exceptJti }` and `revokeByRefreshTokenHash` takes `{ reason }`.

0.4.0 adapters must also persist the new session fields (`kind`, `authTime`, `familyId`, `familyCreatedAt`), and implement `CredentialRepository.updateCounter` and `deleteByCredentialId` as conditional writes that resolve whether they changed anything. See `docs/api/repository-adapters.md`.

**Mongo replica set required for transactions.** `SessionRepository.createSessionForLogin()` — the atomic "write session + audit record + update lastLoginAt" used by login/MFA-verify/SSO — uses a real Mongo transaction (`connection.startSession().withTransaction()`), which requires your MongoDB deployment to be a replica set (including a single-node one) or a sharded cluster. A standalone `mongod` cannot run it. Atlas and most managed Mongo offerings are replica sets by default.

`initIdentityProvider()` checks this at **startup** (a real, read-only, no-op transaction) rather than letting it surface as a confusing failure on someone's first login — see `src/storage/mongo/assert-transactions.js`. If your deployment doesn't support transactions, `initIdentityProvider()` throws an `IdpError` (`code: 'MONGO_TRANSACTIONS_UNSUPPORTED'`) with the fix inline: use `docker-compose.yml` in this repo for local dev, or convert an existing standalone `mongod` in place by restarting it with `--replSet rs0` and running `rs.initiate()` once — no reinstall, existing data is preserved. Set `mongo.skipTransactionCheck: true` in config to skip this probe (e.g. a CI job reusing a known-good cluster) and shave the extra round trip off startup.

## What this package deliberately does not do

- No RBAC decisioning — no scope catalogue, no wildcard permission matcher, no `requirePermission()`/`<Can>` component. Bring your own.
- No message bus, SMTP, or push integration — use the hooks.
- No secrets-vault client (Infisical, AWS Secrets Manager, ...) — resolve your own config values before calling `initIdentityProvider()`.
- No QR-code rendering — `setupMfaHandler` returns the raw `otpauth://` URI; render your own QR code client-side.

## License

MIT © Okeav
