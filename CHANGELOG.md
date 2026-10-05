# Changelog

All notable changes to `@okeav/idp-core` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/) (pre-1.0: a `MINOR` bump may include
backwards-incompatible changes, per the [semver spec's rules for 0.y.z](https://semver.org/#spec-item-4)).

## [0.3.0] - 2026-10-05

A security release. Four issues found while building a platform on 0.2.1, one of them reachable in
production. **Three changes are breaking** — see [Upgrading from 0.2.x](#upgrading-from-02x) below.

### Security

- **OAuth2 client management was unauthenticated (High).** `buildRouter()` mounted
  `/oauth2/clients*` — register, list, get, update, **approve**, **rotate-secret**, deactivate —
  with no authentication at all, so anyone who could reach the router could register and approve a
  client, or rotate an existing client's secret. These routes are now **not mounted** unless you
  pass `buildRouter({ clientManagement: { middleware: [...] } })`, and then only behind that
  middleware (your admin auth), which runs first for every client route. `buildRouter()` throws at
  startup if `clientManagement` is given without at least one middleware function.
- **MFA secrets were stored in plain text.** `mfaSecret` and `mfaTempSecret` are now encrypted at
  rest with AES-256-GCM (`v1:<keyId>:<iv>:<ciphertext>:<tag>`), keyed by `config.mfa.encryptionKey`
  or a pluggable `config.mfa.secretCipher` (e.g. a KMS). The owning user's id is bound as additional
  authenticated data, so a ciphertext copied onto another user's row fails to decrypt. Decryption
  fails closed (`MFA_SECRET_UNREADABLE`, 500) on tampering, the wrong key, or an unknown key id.
  Keys rotate via `config.mfa.previousEncryptionKeys`: decryption accepts any configured key id,
  encryption always uses the current key, and secrets under a retired key are re-encrypted on the
  user's next successful verify. Existing plain-text secrets keep working and are encrypted on the
  next successful verify; `migrateMfaSecrets()` does them all in one pass, and
  `config.mfa.requireEncrypted` then refuses any plain-text value that remains.
- **No per-account limit on MFA attempts.** The only limit was per IP (`mfa-challenge:ip:<ip>`), so
  an attacker who had the password could spread guesses at the 6-digit code across many IPs. Failed
  second-factor attempts are now also counted **per account**, across TOTP, recovery codes,
  WebAuthn-as-MFA, and the codes that confirm enrolment (`POST /me/mfa/confirm`) and disable MFA
  (`DELETE /me/mfa`). By default, 5 failures in 15 minutes lock the account's second-factor step for
  15 minutes (`config.mfa.lockout`). While locked, every attempt returns 429 `MFA_LOCKED` with an
  identical body, even with the right code: the lock is checked before the code. A lockout emits an
  `MFA_LOCKED` audit event (and webhook). A successful verify resets the counter. The count lives in
  storage (new optional `attemptCounterRepository`), so it holds across instances.
- **Rate limiting failed open on backend errors for credential checks.** `enforceRateLimit` let
  every request through when the limiter's backend (e.g. Redis) errored. It now takes a
  `failMode`: login (per IP and per email), MFA verification (TOTP and WebAuthn), password-reset
  and magic-link requests use `'closed'` and return 503 `RATE_LIMITER_UNAVAILABLE`. Token refresh
  keeps an explicit fail-open. WebAuthn MFA verification is now also subject to the per-IP
  `rateLimiting.mfaChallenge` limit.
- **"Log out everywhere" and password reset didn't revoke access tokens.** They revoked every
  session row, but `authContextMiddleware` only consulted a per-process revocation cache, so access
  tokens stayed valid on every other instance until they expired. With the new
  `config.session.verifyOnEachRequest` (default `true`), `authContextMiddleware` checks the
  token's session row (by `jti`) on every request and refuses a token whose row is missing,
  revoked or expired. Logout-all, password reset and change, session revocation, account deletion
  and OIDC end-session now take effect on every instance immediately. The cache remains a fast
  path only: a cached "revoked" short-circuits, but a cached "not revoked" never skips the storage
  check. A storage error fails closed (`SESSION_STORE_UNAVAILABLE`, 503).

### Added

- `buildRouter({ features })`: set `magicLink`, `webauthn`, `sso`, `oauth2`, `oidc` or
  `serviceMesh` to `false` to leave that surface unmounted. All default to `true`; unknown keys throw.
- `migrateMfaSecrets({ batchSize, dryRun })` and `AesGcmSecretCipher` exports.
- Config: `mfa.encryptionKey`, `mfa.previousEncryptionKeys`, `mfa.secretCipher`, `mfa.enabled`,
  `mfa.allowPlaintext`, `mfa.requireEncrypted`, `mfa.lockout`, `session.verifyOnEachRequest`, and
  the matching `configFromEnv` variables (`IDP_MFA_ENCRYPTION_KEY`,
  `IDP_MFA_PREVIOUS_ENCRYPTION_KEYS`, `IDP_MFA_ENABLED`, `IDP_MFA_REQUIRE_ENCRYPTED`,
  `IDP_MFA_ALLOW_PLAINTEXT`, `IDP_SESSION_VERIFY_ON_EACH_REQUEST`).
- Storage interface (both optional, so existing adapters keep working):
  `SessionRepository.findByJti(jti)`, and a new `AttemptCounterRepository`. An adapter without
  `findByJti` falls back to the per-process revocation cache. An adapter without
  `attemptCounterRepository` falls back to an in-process MFA attempt counter. Both log a startup
  warning. The built-in Mongo adapter implements both (new `IdpAttemptCounter` collection with a
  TTL index; the existing `{ jti: 1 }` session index serves the lookup).
- Error codes: `MFA_LOCKED`, `MFA_ENCRYPTION_NOT_CONFIGURED`, `MFA_SECRET_NOT_ENCRYPTED`,
  `MFA_SECRET_UNREADABLE`, `RATE_LIMITER_UNAVAILABLE`, `SESSION_STORE_UNAVAILABLE`, `FEATURE_DISABLED`.
- Access tokens with no session row behind them carry `sessionless: true` and are exempt from the
  per-request session check. These are `client_credentials` tokens and tokens minted through the
  public `issueAccessToken()` / `issueOAuth2AccessToken()` exports; pass `{ sessionless: false }`
  if you created a matching session row yourself.

### Fixed

- **`POST /logout` required `refreshToken` in the body** even though the handler also reads the
  httpOnly `refresh_token` cookie, so cookie-based browser clients couldn't log out through
  `buildRouter()`. The body field is now optional.
- **MFA recovery codes couldn't be used at `POST /mfa/verify`.** Recovery codes are
  `XXXXXX-XXXXXX` (13 characters), but the schema capped `code` at 10, and past the schema otplib
  v13 throws on any non-6-digit token (a 500). Both are fixed.

### Upgrading from 0.2.x

1. **OAuth2 client routes (breaking).** If you use `buildRouter()` and administer OAuth clients over
   HTTP, pass your admin auth: `buildRouter({ clientManagement: { middleware: [requireAdmin] } })`.
   If you don't, do nothing: the routes are simply gone. If you'd added a workaround that 404s
   `/oauth2/clients*` in front of the router, remove it.
2. **MFA key (breaking).** Startup now fails while MFA is enabled (the default) without a key. Set
   `config.mfa.encryptionKey` to 32 random bytes, base64 (`openssl rand -base64 32`), or
   `IDP_MFA_ENCRYPTION_KEY` with `configFromEnv`. Store it like any other secret, because losing it
   locks every MFA user out. Deploy, then run `migrateMfaSecrets()` once. Users who log in first are
   migrated anyway. Then set `config.mfa.requireEncrypted: true`. If you don't use TOTP MFA at all,
   set `config.mfa.enabled: false` instead. `config.mfa.allowPlaintext: true` exists for local
   development only.
3. **Per-request session check (breaking-safe default).** `session.verifyOnEachRequest` is on by
   default and costs one indexed storage read per authenticated request. Set it to `false` to keep
   0.2.x behaviour, where access tokens survive logout-all and password reset/change until they
   expire, on every instance (up to `ttls.accessToken`, 1 hour by default). Those flows never wrote
   the per-process cache, which only records single-session logouts and revocations on the
   instance that handled them. Tokens you minted yourself with `issueAccessToken()`
   are unaffected. A token minted under 0.2.x that has no session row is refused, which matters only
   if you issued one directly and it hasn't expired yet.
4. **Custom storage adapters:** implement `sessionRepository.findByJti` (indexed) and
   `attemptCounterRepository` to make both protections hold across instances (see
   `src/storage/interfaces.js`). Until then the warnings above are logged at startup.
   `@okeav/idp-core-postgres` 0.2.0 implements both.

## [0.2.1] - 2026-08-09

### Fixed

- **`authContextMiddleware`'s published type declaration was missing `optional`.** The JSDoc and
  runtime already supported `authContextMiddleware({ optional: true })` (populate `req.auth` when
  a valid token is present, but don't reject when no token is presented at all — used by routes
  that behave differently for logged-in vs. anonymous callers). `types/index.d.ts` only declared
  `opts?: { issuer?: string }`, so TypeScript consumers passing `optional` got a compile error
  against otherwise-correct, already-working code. No runtime change.

### Documentation

- Added [Storing App-Specific User Data](docs/examples/consumer-managed-app-data.md) — the
  canonical pattern for attaching a `role`/`capabilities`/profile field to a user via a
  consumer-owned collection joined by `user.id`, since idp-core's own `User` record has no such
  field. Cross-linked from Bootstrap & Config and the repository-adapter extension example.
- Documented the `cookies.secure` / `NODE_ENV` interaction in Bootstrap & Config and the
  quickstart/magic-link examples: a plain local run leaves `NODE_ENV` unset, which defaults
  `cookies.secure` to `true` and makes a real browser silently refuse the session cookie over
  `http://` — invisible to `curl`, which doesn't enforce `Secure` at all.

## [0.2.0] - 2026-08-02

### Fixed

- **`POST /oauth2/authorize/deny` no longer accepts an unregistered `redirect_uri`.** The handler
  previously redirected to any well-formed `redirect_uri` in the request body without validating
  it against the named client's registered `redirectUris` — an open-redirect gap that the
  accept/confirm path never had. It now runs the same client-lookup and `redirect_uri` validation
  as `authorizeHandler`/`confirmConsentHandler`. **Behavior change:** a request with an unknown
  `client_id` or an unregistered `redirect_uri` now fails with `OAUTH_CLIENT_NOT_FOUND` /
  `INVALID_REDIRECT_URI` (400) instead of redirecting.
- **`refresh_token` grant no longer widens scope beyond the original consent.** The grant
  previously recomputed the issued scope from the client's *current* `allowedScopes` on every
  refresh, so a refresh exchange could silently grant broader access than the resource owner ever
  consented to (e.g. after an admin later expanded the client's `allowedScopes`). It now narrows
  the scopes captured at the original authorization against the client's current `allowedScopes`,
  so a refresh can only hold steady or shrink, never widen. **Behavior change:** the `scope` in a
  refresh response may now be narrower than before for clients whose `allowedScopes` exceeds what
  was actually consented to.
- **A `REVOKED` signing key's tokens are now actually rejected.** Token verification
  (`verifyWithAnyKey` → `getPublicKeyByKid`) previously resolved a key purely by matching `kid`
  against the registry, ignoring `status` entirely — a token signed by a key marked `REVOKED` (or
  even just removed from active use) still verified successfully as long as its `kid` was still
  configured. `getPublicKeyByKid` now refuses to resolve a `REVOKED` key, so previously-issued
  tokens signed by it now correctly fail with `INVALID_TOKEN` (401). `ACTIVE`/`ROTATING`/`RETIRED`
  keys are unaffected — a `RETIRED` key still verifies tokens issued during its rotation grace
  period, matching what `/keys/:kid` already allowed. **Behavior change:** if you were relying on
  `REVOKED` keys continuing to verify (unlikely, since that defeats the purpose of marking a key
  revoked), tokens signed by them will now be rejected.

### Docs

- Moved hand-written API reference and examples into this repo (`docs/`) as the source of truth
  for `@okeav/idp-core` documentation, previously maintained only on the consuming platform repo.
- Verified all 31 moved doc files against current source and corrected every discrepancy found —
  see the full file list in this release's commits for specifics (stale claims about scope
  recomputation, error codes that don't match what's actually thrown, an unusable copy-pasteable
  example, missing config options, and a few others).

## [0.1.0] - 2026-07-24

Initial release.
