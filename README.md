# @okeav/idp-core

A standalone, pluggable identity provider for Node.js/TypeScript backends — OAuth2/OIDC authorization server, password + MFA + WebAuthn/passkeys + magic-link + social login, session management, rate limiting, outbound webhooks, and service-to-service JWKS trust. Bring your own MongoDB; everything else (Redis, RabbitMQ, Elasticsearch, a secrets vault) is optional or entirely absent.

Extracted from and generalized out of Okeav's internal `auth-service`. Business-specific concepts (account types, roles, capability scopes) are deliberately **not** part of this package — it issues and verifies opaque `claims` on your behalf without ever interpreting them. Bring your own RBAC layer.

## Install

Requires Node >=20 (needed by `@simplewebauthn/server`, a direct dependency used for the WebAuthn/passkey endpoints — installed automatically, no separate `npm install` step).

```bash
npm install @okeav/idp-core
npm install express cookie-parser   # peer dependencies you likely already have
npm install ioredis                 # only if you use the Redis cache adapter (also shared by the Redis rate-limiter adapter)
```

## Local development

```bash
docker compose up -d   # single-node Mongo replica set (rs.initiate() already run) + Redis
npm test                # runs the critical-path suite against an in-memory Mongo replica set
```

See `examples/express-quickstart/` for a complete, copy-pasteable server wired against the compose stack above — start there if you want to see the package running before reading the config reference below.

## Quick start

```js
import express from 'express';
import { initIdentityProvider, buildRouter, cookieParser, configFromEnv } from '@okeav/idp-core';

await initIdentityProvider({
  ...configFromEnv(), // reads the IDP_* env vars documented in .env.example
  hooks: {
    onVerificationEmailRequested: async ({ email, verificationCode }) => {
      await sendEmail(email, `Your verification code is ${verificationCode}`);
    },
    resolveAuthContext: async (user) => ({ claims: { role: 'member' } }),
  },
});

const app = express();
app.use(cookieParser());
app.use(express.json());
app.use('/auth', buildRouter());

app.use((err, req, res, next) => {
  // Every error this package throws is an IdpError — see "Error handling" below.
  res.status(err.httpStatus || 500).json({ error: err.code || 'INTERNAL_ERROR', message: err.message });
});

app.listen(3000);
```

Prefer wiring routes yourself? Every handler in `buildRouter()` is also a named export — `import { loginHandler } from '@okeav/idp-core'` — so you can mount them on your own router with your own paths, rate limiters, and middleware order.

## Configuration

See `.env.example` for the full list of environment variables and `types/index.d.ts` for the `IdpConfig` shape. Required fields:

- `issuer` — this IDP's URL, used as the JWT `iss` claim.
- `mongo.uri` (or `mongo.connection` — an existing Mongoose connection).
- `signingKeys.keys` — at least one `ACTIVE` RS256 keypair (PEM or base64 PEM).
- `security.emailHashPepper` — HMAC key for the email blind index.
- `security.tokenHashSecret` — HMAC key for hashing opaque refresh/reset/verification tokens at rest.

Everything else has a sensible default. RBAC-shaped config (roles, scopes, capabilities) doesn't exist in this schema on purpose — see "Claims are opaque" below.

### Cache adapter

`config.cache.adapter` is `'memory'` (default) or `'redis'`.

- **memory** — zero config, but single-process only. State (revocation cache, SSO CSRF state) is lost on restart and not shared across instances. Fine for local dev or a genuinely single-instance deployment; wrong for anything horizontally scaled.
- **redis** — set `config.cache.adapter = 'redis'` and `config.cache.redis = { host, port, password }`. Requires `ioredis` as a peer dependency; it's only `import()`-ed when this adapter is actually selected.

**Revocation checks fail closed regardless of adapter**: if the cache adapter throws (connection down, timeout), `authContextMiddleware` rejects the request rather than treating the failure as "not revoked." A cache *miss* (key genuinely absent) still correctly means "not revoked" — only adapter *errors* trigger the fail-closed path.

### Claims are opaque

`issueAccessToken({ sub, email, claims })` — `claims` is whatever object you pass. It comes back untouched as `req.auth.claims` after `authContextMiddleware`. This package never validates its shape, and ships no scope-matching or permission-checking logic — that's your application's job (or a separate RBAC package).

For login flows that mint a session on your behalf (password login, MFA-verify, SSO callback), configure `hooks.resolveAuthContext(user, ctx)` to build that `claims` object — it's called synchronously right before the token is issued and defaults to `() => ({})` if you don't supply one.

`POST /refresh` does **not** call `resolveAuthContext` again by default — the refreshed access token carries forward the `claims` snapshot taken at login, for the life of that refresh-token session. That means a capability/role change you make mid-session (e.g. an admin revokes a permission) only takes effect once the user's refresh token itself is replaced by a fresh login, not at the next access-token rotation. Set `config.session.reresolveClaimsOnRefresh: true` to have `/refresh` re-invoke `resolveAuthContext(user, { isNewUser: false, method: 'refresh' })` on every call instead, so changes take effect within one access-token TTL — at the cost of one extra call to your hook (and whatever it looks up) on every refresh.

### Event hooks

All hooks are optional, default to no-ops, and are awaited-but-never-thrown — a hook that throws is logged and swallowed, never breaks the request it's attached to.

| Hook | Fires on |
|---|---|
| `onAuditLog(event)` | Every audit-worthy action (login, logout, password change, MFA changes, OAuth2 grants, admin actions, SSO events, etc.) — `event.action` identifies which one. |
| `onVerificationEmailRequested` | Registration and resend-verification. |
| `onPasswordResetRequested` | Forgot-password. |
| `onPasswordChanged` | Password change/reset completed. |
| `onSuspiciousActivityDetected` | Account locked after too many failed logins. |
| `onNewDeviceLogin` | Login from a browser/OS combination not seen before for this user. |
| `onMagicLinkRequested` | Magic-link login requested — carries the raw token to embed in the emailed link. |
| `resolveAuthContext(user, ctx)` | Password login, MFA-verify, SSO callback, magic-link verify, WebAuthn login — builds the access token's `claims`. Also called on `/refresh` if `config.session.reresolveClaimsOnRefresh: true` (default false). |

This package never talks to a message bus, SMTP server, or push provider directly — wire your own inside these hooks.

### Rate limiting

Request-rate limiting is enabled by default (`config.rateLimiting.enabled = true`) and is a distinct concern from `security.maxFailedLoginAttempts` (which permanently locks one account after N wrong passwords). Rate limiting instead throttles the *rate* of requests to a handful of sensitive endpoints within a rolling fixed window, regardless of whether individual requests succeed:

| Endpoint | Default limit |
|---|---|
| Login, per IP | 10 / 15 min |
| Login, per email | 5 / 15 min |
| Password reset request, per IP | 3 / hour |
| MFA challenge verification, per IP | 5 / 15 min |
| Refresh token, per IP | 30 / min |
| Magic-link request, per IP | 3 / hour |

Override any of these under `config.rateLimiting.{login, loginByEmail, passwordReset, mfaChallenge, refreshToken, magicLink}` — each takes `{ max, windowSeconds }`. Set `config.rateLimiting.enabled = false` to disable entirely if you already rate-limit at a gateway/CDN layer (e.g. Cloudflare, an API gateway) — running it twice is redundant, not harmful, but the extra storage round-trip on every request is pure overhead if a layer in front of this service already enforces it.

Uses the same adapter pattern as the cache layer: `config.rateLimiting.adapter` is `'memory'` (default, single-process) or `'redis'` (shares the cache adapter's Redis connection automatically if `config.cache.adapter` is also `'redis'`, otherwise set `config.rateLimiting.redis` separately).

**Fails open, deliberately** — the inverse of the cache layer's revocation check. If the rate limiter's backend errors (Redis down, timeout), the request is allowed through and the error is logged, rather than locking users out because of an infrastructure hiccup. Rate limiting here is defense-in-depth, not a security invariant the way revocation checking is.

### Magic link (passwordless email login)

`requestMagicLinkHandler` / `verifyMagicLinkHandler` — a single-use, time-limited (`ttls.magicLink`, default 15 min) email link, built on the same `VerificationTokenRepository` as email verification and password reset (no separate storage). Requesting a link for an unknown email creates a new `PENDING_VERIFICATION` user and fires `onMagicLinkRequested` with the raw token to embed in your emailed link — gated by `config.magicLink.allowSignupViaMagicLink` (default `true`; set `false` for invite-only apps where an unrecognized email should silently no-op instead of signing someone up).

Verifying the token goes through the exact same `resolveAuthContext` → session-issuance path as every other login method — there's no separate, weaker code path for magic-link sessions.

### WebAuthn / passkeys

Six ceremony endpoints across three flows, all opt-in behind `config.webauthn.{rpID, rpName, origin}` (validated lazily on first use, not at `initIdentityProvider()` startup, so consumers who don't use passkeys never need to configure it). `rpID` must be the **frontend's** registrable domain — not necessarily this API's own hostname if the API lives on a subdomain.

| Flow | Endpoints | Auth required? |
|---|---|---|
| Register a passkey on an existing account | `generateRegistrationOptionsHandler`, `verifyRegistrationHandler` | Yes |
| Primary passwordless login | `generateAuthenticationOptionsHandler`, `verifyAuthenticationHandler` | No |
| Passkey as an MFA second factor (alternative to TOTP) | `generateMfaWebauthnChallengeOptionsHandler`, `verifyMfaWebauthnChallengeHandler` | No (gated by a valid `mfaChallengeToken` instead) |

Primary login supports both usernameless/discoverable credentials (omit `email` when requesting options) and email-scoped `allowCredentials`. Both the primary-login and MFA-second-factor verify handlers resolve through the same `resolveAuthContext` → session-issuance path as password/SSO/magic-link login. The MFA path additionally checks server-side that the verified credential actually belongs to the challenged user (not just whatever credential ID the client submitted) as defense-in-depth beyond the challenge scoping.

Credentials are stored via a new `CredentialRepository` interface (`src/storage/interfaces.js`) alongside the other seven — see "Storage" below.

### Outbound webhooks

Additive to the in-process hooks above — set `config.webhooks.endpoints = [{ url, secret }, ...]` and every `onAuditLog`/named hook event *also* gets POSTed as a signed JSON payload (`resolveAuthContext` is excluded, since it's a data-returning callback rather than a one-way event). Leave `endpoints` empty (the default) to disable entirely.

Each delivery is a fire-and-forget background operation — a webhook endpoint being slow, erroring, or completely unreachable never blocks or fails the auth request that triggered it. Failed deliveries retry with exponential backoff (`config.webhooks.maxAttempts`, default 5; `config.webhooks.retryBaseDelayMs`, default 500ms, doubling each attempt) before being logged and dropped.

Request body:

```json
{ "event": "LOGIN", "payload": { "userId": "...", "email": "..." }, "timestamp": "2026-01-01T00:00:00.000Z" }
```

Headers:

- `X-Idp-Event` — the event name (an `onAuditLog` action like `LOGIN`/`REGISTERED`/`PASSWORD_CHANGED`, or a named-hook event like `onMagicLinkRequested`).
- `X-Idp-Delivery` — a UUID unique per delivery attempt sequence, for dedup on your end.
- `X-Idp-Signature` — `t=<unix seconds>,v1=<hex HMAC-SHA256>`, computed over `` `${t}.${rawBody}` `` with your configured `secret` (Stripe-style signing).

Verify it on your receiving end with the exported `verifyWebhookSignature(secret, rawBody, signatureHeader)` helper — `rawBody` must be the exact, unparsed request body bytes/string (verify before you `JSON.parse`).

### Service-to-service JWKS trust

A differentiator kept from the source this was extracted from: any number of your own backend services can register an S2S signing keypair with this IDP (`initServiceIdentity`) and mint short-lived RS256 tokens to call each other (`mintServiceToken`), verified either in-process (`serviceContextMiddleware`, if the verifying service also runs this package) or over HTTP against `/.well-known/services-jwks.json` (`verifyServiceTokenRemote`, for services that don't).

### SSO / social login

Google, GitHub, Microsoft (Entra ID — defaults to the `common` multitenant endpoint, supporting both work/school and personal Microsoft accounts), Apple, and LinkedIn. Configure whichever you use under `config.oauthProviders`.

The callback is a **single step** — it resolves the identity, calls `hooks.resolveAuthContext`, and mints the full session directly. (An earlier two-step "exchange token" design existed in the source this was extracted from, purely because identity resolution and role/permission resolution lived in two different internal services there — not for any redirect-URI or CSRF-security reason. If you need that same split, implement it inside your own `resolveAuthContext`.)

`config.sso.allowedRedirectOrigins` is an optional allowlist for the `redirect_uri` query param `initiateSsoHandler` accepts — set it in production to prevent open-redirect abuse; if omitted, no check is performed.

### Error handling

Every error this package throws is an `IdpError` (`{ code, httpStatus, message, cause? }`) passed to `next(err)`. The package never shapes an HTTP response body itself — write one Express error-handling middleware that maps `err.httpStatus` / `err.code` to your API's response envelope. See `ERROR_CODES` for the catalogue of codes you might see.

## Storage

MongoDB is the only concrete storage adapter shipped in this version, behind eight repository interfaces (`UserRepository`, `SessionRepository`, `AuthorizationCodeRepository`, `ConsentRepository`, `OAuthClientRepository`, `VerificationTokenRepository`, `ServiceKeyRepository`, `CredentialRepository` — documented in `src/storage/interfaces.js`). A future adapter (Postgres, DynamoDB, ...) implements the same eight interfaces; nothing above the storage layer needs to change.

**Mongo replica set required for transactions.** `SessionRepository.createSessionForLogin()` — the atomic "write session + audit record + update lastLoginAt" used by login/MFA-verify/SSO — uses a real Mongo transaction (`connection.startSession().withTransaction()`), which requires your MongoDB deployment to be a replica set (including a single-node one) or a sharded cluster. A standalone `mongod` cannot run it. Atlas and most managed Mongo offerings are replica sets by default.

`initIdentityProvider()` checks this at **startup** (a real, read-only, no-op transaction) rather than letting it surface as a confusing failure on someone's first login — see `src/storage/mongo/assert-transactions.js`. If your deployment doesn't support transactions, `initIdentityProvider()` throws an `IdpError` (`code: 'MONGO_TRANSACTIONS_UNSUPPORTED'`) with the fix inline: use `docker-compose.yml` in this repo for local dev, or convert an existing standalone `mongod` in place by restarting it with `--replSet rs0` and running `rs.initiate()` once — no reinstall, existing data is preserved. Set `mongo.skipTransactionCheck: true` in config to skip this probe (e.g. a CI job reusing a known-good cluster) and shave the extra round trip off startup.

## What this package deliberately does not do

- No RBAC decisioning — no scope catalogue, no wildcard permission matcher, no `requirePermission()`/`<Can>` component. Bring your own.
- No message bus, SMTP, or push integration — use the hooks.
- No secrets-vault client (Infisical, AWS Secrets Manager, ...) — resolve your own config values before calling `initIdentityProvider()`.
- No QR-code rendering — `setupMfaHandler` returns the raw `otpauth://` URI; render your own QR code client-side.

## License

MIT © Okeav
