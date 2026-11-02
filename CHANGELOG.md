# Changelog

All notable changes to `@okeav/idp-core` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/) (pre-1.0: a `MINOR` bump may include
backwards-incompatible changes, per the [semver spec's rules for 0.y.z](https://semver.org/#spec-item-4)).

## [Unreleased] - 0.4.0

A security release from a full audit of 0.3.0. **Breaking** — see the upgrade notes under each item.

### Security

- **OAuth2 access tokens worked as first-party credentials (Critical).** `verifyAccessToken` and
  `authContextMiddleware` checked signature, issuer and `type`, but never *who the token was issued
  to*. A token minted for a third-party OAuth2 client (`aud` = that client) passed on every IdP route,
  so any relying party a user authorized — even for `openid` alone — could delete the account,
  register its own passkey (a permanent login), change the password with a known one, or grant itself
  consent for every scope. Access tokens are now classified as `first-party`, `oauth2-user` or
  `oauth2-client` (client_credentials, now marked `gty: 'client_credentials'`), and both accept only
  `first-party` with `aud` = the issuer by default. `/userinfo` accepts only `oauth2-user` tokens.
  **Upgrade:** a resource server that accepts OAuth2 tokens must opt in with
  `authContextMiddleware({ accept: ['oauth2-user'] })` (and/or `'oauth2-client'`) and check
  `req.auth.scopes`. A first-party token minted with a custom `audience` needs
  `authContextMiddleware({ audience })`. `req.auth.userId` is now `undefined` for client_credentials
  tokens (it used to be the client id); `req.auth` gains `tokenKind`, `clientId`, `scopes`.
- **Refresh tokens were interchangeable (High).** A refresh token from an OAuth2 grant was accepted
  at the first-party `POST /refresh` (minting a first-party session with no client authentication),
  a first-party refresh token was accepted by the OAuth2 `refresh_token` grant, and any client could
  redeem another client's refresh token. Session rows now carry `kind: 'first_party' | 'oauth2'`;
  `/refresh` accepts only `first_party`, and the OAuth2 grant only `oauth2` rows issued to the calling
  client. A token presented in the wrong place stays revoked. Rows written before 0.4.0 are classified
  by their stored claims (`{ clientId, scopes[] }` = OAuth2). **Upgrade (custom storage adapters):**
  persist the new `kind` field on session rows.
- **One request could crash the process on Express 4 (High).** `POST /oauth2/token` returned the
  grant handler's promise without awaiting it, so a failed grant (e.g. an unknown `client_id`)
  escaped the handler's `try/catch`; Express 4 ignores returned promises, so it became an unhandled
  rejection, which terminates Node ≥ 15. `GET /userinfo` had no error handling at all.
- **`/userinfo` released email without the `email` scope**, did not require `openid`, and answered for
  suspended/deleted users. It now requires `openid`, releases `email` / profile claims only for the
  matching scopes, refuses inactive users, and sends `Cache-Control: no-store`.
- **SSO linked accounts by an unverified email (Critical).** With no local account linked to a
  provider identity yet, the callback attached it to whichever account had the same email, without
  checking that the provider had verified the address. Anyone able to put an arbitrary email on a
  provider account logged in as its owner — most simply via Microsoft (`mail` is set by the tenant
  admin; with the default `common` authority any tenant qualifies — "nOAuth"). SSO now creates or
  links an account by email only when the provider asserts `email_verified` (Google, Apple,
  LinkedIn); GitHub uses only the account's primary *verified* address (never the public profile
  email); Microsoft's address is trusted only when `oauthProviders.microsoft.tenant` names a single
  tenant, or with an explicit `trustEmail: true`. A refusal redirects with `error=email_not_verified`.
  Identities already linked keep logging in by provider id. **Upgrade:** with Microsoft on the
  `common` authority, new users can no longer sign up or link through Microsoft.
- **SSO and magic-link login skipped MFA (High).** Both issued a full session to accounts with MFA
  enabled. They now stop at the MFA challenge like password login: magic-link verify answers
  `{ mfaRequired, mfaChallengeToken, expiresIn }`; the SSO callback redirects to `redirect_uri` with
  `#mfa_required=1&mfa_challenge_token=…&expires_in=…` (in the fragment, so it never reaches a server
  log or `Referer`) and sets no cookies. **Upgrade:** handle both responses in your frontend.
- **Pre-registration account takeover (High).** An attacker could register the victim's email with a
  password of their choosing; when the account was later activated — by the victim verifying their
  "own" registration (a repeat registration was silently accepted, keeping the first password), by a
  magic link, or through SSO — the attacker's password worked. Now: registering an address that is
  still pending replaces its password and invalidates earlier codes before sending a fresh one;
  activation by magic link or SSO discards any password (and MFA state) set before the address was
  proven. SSO never attaches a login method to a locked/suspended/deleted account.
- **SSO login CSRF, no PKCE, no nonce (Medium).** The SSO `state` was only a cache key, so an
  attacker could start a login with their own provider account and have a victim's browser finish
  it, signing the victim into the attacker's account. `GET /sso/:provider` now also sets a
  per-attempt httpOnly binding cookie (SameSite=Lax; SameSite=None;Secure for Apple's form POST),
  and the callback completes only with it. The state is consumed atomically and checked *before*
  anything else, including a provider `error` (which is no longer reflected — the callback redirects
  with `error=provider_error`). Google, Microsoft and GitHub exchanges use PKCE (S256); Apple's
  `id_token` must carry this login's `nonce` and the right `iss`/`aud`/`exp`. **Upgrade:** mount
  `cookie-parser` before the router (already needed for cookie sessions).
- **Webhooks carried login credentials to every endpoint (High).** `onPasswordResetRequested`,
  `onMagicLinkRequested` and `onVerificationEmailRequested` payloads — live reset tokens, magic-link
  tokens, verification codes — were POSTed to every configured endpoint, so anyone with access to
  any receiver (or its logs, or its retry queue) could take over any account. Those fields are now
  stripped unless the endpoint sets `includeCredentials: true` (your mail sender). Endpoints can
  filter by `events`, must be `https` (`http` only for localhost) with a secret of ≥ 16 characters
  (checked at startup), and redirects are no longer followed. The delivery id is now inside the
  signed body (`id`) as well as the `X-Idp-Delivery` header — de-duplicate on the body's. 
  `verifyWebhookSignature` accepts an array of secrets and several `v1` signatures (rotation).
  Webhooks are still sent when the in-process hook throws; at most `webhooks.maxInFlight` (100)
  deliveries run at once (logged URLs omit credentials and query strings). **Upgrade:** set
  `includeCredentials` on the endpoint that sends emails, if one does.
- **Hook timing and stalls.** Every hook is awaited at most `hookTimeoutMs` (default 10 s), so a hung
  consumer callback can't stall a login. On the endpoints that must not reveal whether an account
  exists — register, resend verification, forgot password, magic-link request — the email hooks (and
  their audit events) are started but not awaited: waiting for an email to be sent made those
  responses measurably slower for real accounts. **Upgrade:** in serverless runtimes, make those
  hooks hand off quickly (enqueue rather than send inline).
- **Service impersonation through the shared bootstrap secret (High).** Every service presented the
  same `serviceMesh.bootstrapSecret`, and `POST /internal/service-keys` trusted the `name` in the
  body — any participating service (or anyone who read its environment) could register a key as
  `billing` and mint tokens that pass as billing. New `serviceMesh.bootstrapSecrets: { name: secret }`
  gives each service its own credential, covering only its own name (and letting it rotate: previous
  keys go ROTATING, then RETIRED). The shared secret still works but can only register a name with no
  key yet — replacing another service's key answers 409 `SERVICE_NAME_TAKEN`.
  `serviceMesh.allowedServiceNames` restricts names; new `revokeServiceKey(kid)`. Keys must be RSA
  public keys of ≥ 2048 bits (a private key PEM used to be accepted and *served*); names must match
  `^[a-z0-9][a-z0-9-]{0,62}$`. Secrets are compared in constant time and registration is rate
  limited (`rateLimiting.serviceKeyRegistration`). **Upgrade:** prefer `bootstrapSecrets`.
- **`tokenMode: 'both'` let a shared-secret caller claim any name (Medium).** The default is now
  `'token'` (also in `configFromEnv`). `requireServiceCallerMiddleware` refuses shared-secret callers
  (their `x-service-name` is unverified) unless `serviceMesh.allowLegacySecretCallers: true`. A
  missing `ownServiceName` used to make every token check fail and silently fall back to the secret;
  it is now a 500 `SERVICE_NOT_CONFIGURED`.
- **Service tokens could live forever.** Tokens without `exp`, with a lifetime over 5 minutes, or
  with `iat` in the future are refused.
- **Remote key lookups could be forced on every request.** Each unknown `kid` refetched the IdP's
  services JWKS — no credentials needed. Forced refreshes now happen at most every 30 s, fetches time
  out, a failed refresh keeps the last good keys (with a 30 s backoff), and `verifyServiceTokenRemote`
  caches its lookup per IdP URL (it fetched on every call). The in-process lookup reads one key by
  index instead of scanning all of them.
- **SSO redirect allowlist was opt-in (open redirect).** With any provider configured,
  `initIdentityProvider()` now requires `sso.allowedRedirectOrigins` (exact origins) and an absolute
  `sso.baseCallbackUrl`; only `https` (or `http://localhost`) targets on the list are accepted.
  **Upgrade:** set both.
- **SSO robustness.** Provider calls time out (`sso.providerTimeoutMs`, default 10 s) and don't
  follow redirects; Apple's generated client secret lives 5 minutes (was ~6 months); the
  pass-through query params given to `resolveAuthContext` as `extra` are limited to 10 short string
  values (they are attacker-controllable — never trust them); `GET /sso/:provider` is rate limited
  per IP (`rateLimiting.ssoInitiate`).
- **The 6-digit email-verification code could be brute-forced (High).** `/register/verify-email`
  had no rate limit and no attempt limit, against a code valid for 24 hours. Wrong codes/tokens now
  count per account (`security.verificationCodeLockout`, default 5 per hour); the attempt that
  exhausts the budget deletes every outstanding code, and further attempts get 429
  `VERIFICATION_LOCKED`. Attempts are counted *before* the code is checked, so a concurrent burst
  gets no more guesses than the budget. Codes are now stored as HMACs (codes issued before 0.4.0,
  stored in plain text, keep working until they expire). New per-IP limits on `/register`,
  `/register/resend-verification` (`rateLimiting.register`) and `/register/verify-email`
  (`rateLimiting.emailVerification`), and a per-address limit on verification emails
  (`rateLimiting.verificationEmailByEmail`), all fail-closed.
- **Account enumeration.** `/register/verify-email` answered 404 `USER_NOT_FOUND` for unknown
  addresses and `ok` for verified ones; `/register/resend-verification` answered 400
  `EMAIL_ALREADY_VERIFIED`. Both now answer the same for every address (verify: 400
  `INVALID_OR_EXPIRED_TOKEN`; resend: `{ status: 'ok' }`). **Upgrade:** a second click on an
  already-used verification link now gets 400 instead of `ok`.
- **PKCE was optional, `plain` was accepted, and it could be downgraded (High).** A public client
  could run the code flow with no PKCE at all, so an intercepted code was redeemable by anyone with
  the (public) `client_id`. PKCE is now required for public clients always and, by default, for every
  client (`oauth2.requirePkce: 'all'`; set `'public'` to exempt confidential clients). Only `S256`
  is accepted (a challenge without `code_challenge_method=S256` is refused, since the spec default is
  `plain`), the challenge and verifier formats are validated, the comparison is constant-time, and a
  `code_verifier` sent for a code issued *without* a challenge is refused (RFC 9700 §4.8.2).
  **Upgrade:** send `code_challenge` + `code_challenge_method=S256` from every client.
- **Consent could be forged (Medium).** `POST /oauth2/authorize/confirm` granted whatever
  `client_id`, `scope` and `redirect_uri` its body named, with nothing tying it to a request the user
  had seen — cross-site (with `SameSite=None` cookies), or from a sibling origin, a single POST
  granted an attacker's client every allowed scope. `GET /oauth2/authorize` now stores the validated
  request server-side and answers `consent_required` with a single-use, user-bound
  `consent_challenge`; confirm and deny take only `{ consent_challenge }`. **Upgrade:** your consent
  page posts the challenge it received, not the request parameters.
- **OIDC `nonce` protected nothing.** It was dropped at `/authorize` and taken from the *token*
  request instead (chosen by whoever redeems the code). It is now accepted at `/authorize`, stored
  with the code, and echoed into the ID token; a `nonce` at the token endpoint is ignored.
- **ID tokens released email and profile regardless of scope.** Claims now follow the granted
  scopes (`email` → `email`, `email_verified`; `profile` → `name`, `picture`, …). ID tokens also
  carry `azp` and `auth_time`, and honour the client's `idTokenTTL`.
- **Client authentication.** `client_secret_basic` was advertised but never read; it is now
  implemented per RFC 6749 §2.3.1 (form-decoded; one method per request). Every failure — unknown,
  inactive, wrong secret — answers the same 401 `INVALID_CLIENT`. New client secrets are stored as
  HMAC-SHA256 (they are 256-bit random; bcrypt added nothing but a ~250 ms thread-pool cost per
  attempt, a cheap way to stall the whole server); existing bcrypt hashes still verify and are
  upgraded on use. `/oauth2/token`, `/token/revoke` and `/token/introspect` are rate limited per IP
  (`rateLimiting.oauth2Token`) and answer with `Cache-Control: no-store`. Token-endpoint errors use
  the RFC 6749 codes: `INVALID_CLIENT`, `INVALID_GRANT`, `INVALID_SCOPE`, `UNAUTHORIZED_CLIENT`,
  `UNSUPPORTED_GRANT_TYPE`.
- **Revocation and introspection were unauthenticated.** `/oauth2/token/revoke` revoked any refresh
  token for anyone (first-party ones included); `/oauth2/token/introspect` answered any logged-in
  user about any refresh token, and never recognised access tokens. Both now require client
  authentication (introspection: a confidential client), act only on tokens issued to the calling
  client, and handle access tokens (JWT) as well as refresh tokens.
- **Revoking consent or deactivating a client left its tokens working.** Both now revoke the
  client's sessions — that user's, or every user's — and the access tokens paired with them. New
  storage method `SessionRepository.revokeForClient(clientId, { userId? })`.
- **`GET /oidc/end-session` signed the user out everywhere on any token it was shown.** Any ID
  token (handed to every relying party), and even the pre-MFA challenge token, made it revoke all of
  the user's sessions — via a GET any site can trigger. The hint must now be an ID token; it ends
  only the hinted client's sessions for that user, plus the browser's own IdP session if its cookie
  came with the request (cookies are cleared). Expired hints are accepted, per the spec.
- **Client redirect URIs** must be `https` (or `http` to a loopback host, or a reverse-DNS
  private-use scheme for native apps) and may not contain a fragment or credentials;
  `javascript:`/`data:` URIs were previously registrable. Authorization responses carry `iss`
  (RFC 9207). `GET /oauth2/consent` validates its query (`?client_id[$ne]=` reached the database
  on Express 4), and hides clients that aren't active.
- **Logout didn't clear cookies when `cookies.domain` was set** (they were cleared host-only).
- **Stolen refresh tokens went undetected (Medium).** Replaying an already-rotated refresh token was
  simply refused, so whoever rotated first (the thief) kept the chain. Refresh tokens now belong to a
  *family* (one login, or one authorization code); a rotated token presented again revokes the whole
  family — on `/refresh` and the OAuth2 grant alike — and emits `REFRESH_TOKEN_REUSE_DETECTED`.
  Within `session.refreshReuseGraceSeconds` (default 10 s; two tabs refreshing at once) a replay is
  only refused. Redeeming an authorization code twice now revokes everything the first redemption
  issued (`OAUTH2_CODE_REUSE_DETECTED`).
- **Sessions never ended while in use.** Each refresh slid the expiry another 30 days. A family now
  ends `session.absoluteLifetimeSeconds` (default 90 days) after its login, and no refresh token
  outlives that.
- **A refresh racing "log out everywhere" could survive it.** Logout-all, password reset/change and
  account deletion now record `sessionsRevokedAt` on the user before revoking, and a refresh
  re-checks it after writing its successor.
- **The `onNewDeviceLogin` alert never fired:** the check ran after the login's own session row was
  written, so the device was always "known". It now runs before.
- **A locked account told right passwords from wrong ones** (423 vs 401), turning the lockout into
  an oracle. While locked, every password gets the same 401 `INVALID_CREDENTIALS`; a password reset
  lifts the lock.
- **Password reset hygiene.** A new reset request invalidates earlier links, a completed reset
  invalidates every outstanding one, deleted accounts are not sent links, and requests are limited
  per address as well as per IP (`rateLimiting.passwordResetByEmail`).
- Storage interface (optional for now, with graceful degradation): `SessionRepository.revokeFamily`,
  `revokeForClient`, `AuthorizationCodeRepository.findUsedByCodeHash`; `revokeByRefreshTokenHash`
  takes `{ reason }`. Session rows gain `kind`, `authTime`, `familyId`, `familyCreatedAt`.
- **The per-account MFA lockout could be raced (High).** 0.3.0 checked the lock, then the code, and
  only then counted a failure, so a burst of concurrent requests had every guess checked (1,000
  parallel guesses against a limit of 5 were all evaluated). Attempts are now counted *before* the
  code is checked: the counter's atomic increment is the gate, so a burst gets exactly
  `mfa.lockout.maxFailedAttempts` guesses. A success still resets the count. As before, the wrong
  guess that exhausts the budget answers 429 `MFA_LOCKED`, and so does every attempt while locked.
  (An attempt that fails for another reason, e.g. an expired WebAuthn challenge, now also counts.)
- **TOTP codes and MFA challenge tokens could be replayed (Medium).** A code was accepted any number
  of times within its ±30 s window (including the code that confirmed enrolment), and a challenge
  token could complete any number of logins for its 5 minutes. Each account now records the last
  accepted TOTP time step (atomically) and refuses that step or an earlier one; a challenge token
  completes one login only, and one issued before the account's last password change is void.
  **Upgrade:** a user can't log in twice with the same code — they wait for the next one.
- **A recovery code could be spent twice by concurrent requests**, and the write marked a code *by
  index*, so a concurrent regeneration could mark the wrong code. Recovery codes are now spent with
  one atomic conditional update. They are also accepted regardless of case and surrounding spaces.
- **`POST /me/mfa/recovery-codes` needed only the password** — anyone with a session and the
  password could mint fresh second factors. It now also requires a current TOTP `code`.
  **Upgrade:** send `{ password, code }`.
- **Passwordless accounts could not disable MFA or regenerate recovery codes** (both demanded a
  password the account doesn't have). `password` is now required only when the account has one.
- Wrong MFA codes no longer also count toward the *password* lockout (`failedLoginAttempts`); the
  MFA lockout has its own counter.
- **A stolen session could become permanent access (Medium).** Registering a passkey, enrolling MFA
  and deleting the account needed only a valid access token, and a passkey is a login of its own
  that survives logout-all and password reset (with no way to list or remove it). Access tokens now
  carry `auth_time` (the last real login — kept unchanged across refreshes), and the new
  `requireRecentAuth()` middleware (exported) refuses with 401 `REAUTHENTICATION_REQUIRED` unless
  that login is within `session.recentAuthMaxAgeSeconds` (default 15 min). It guards passkey
  registration, `/me/mfa/setup` and `/confirm`, `DELETE /me`, and the new `DELETE
  /me/passkeys/:credentialId`. New `GET /me/passkeys`. **Upgrade:** on `REAUTHENTICATION_REQUIRED`,
  send the user through a login and retry. Sessions created before 0.4.0 have no `auth_time` and
  count as not recent.
- **WebAuthn hardening.**
  - Primary passkey login and passkey registration now *explicitly* require user verification
    (they relied on a library default). WebAuthn-as-MFA explicitly doesn't — its options already
    said `discouraged`, but verification then demanded UV, failing PIN-less security keys.
  - A discoverable assertion's `userHandle` must name the credential's owner.
  - Challenges are redeemed with a new atomic `cache.take()` (MULTI GET+DEL on Redis) instead of
    get-then-delete, and the signature counter is written only if it advanced (atomically), so
    neither a challenge nor a cloned authenticator's assertion can be used twice concurrently.
  - Given an `email`, `POST /webauthn/authentication/options` returned that account's credential
    ids, telling anyone whether the address had an account with passkeys. `email` is now
    ignored unless `webauthn.allowCredentialsByEmail: true`, and then unknown addresses get a stable
    decoy id and no transports are listed.
  - The unauthenticated passkey-login endpoints are rate limited per IP
    (`rateLimiting.webauthnAuthentication`, 60 / 5 min, fail-closed); each options call used to
    park a challenge in the cache with no limit.
  - `CredentialRepository.updateCounter` now resolves whether the counter advanced, and
    `deleteByCredentialId` whether a credential was deleted. **Upgrade (custom adapters):**
    implement both as conditional writes, and add `take()` to a custom cache adapter.
- Storage interface: `UserRepository.claimTotpStep(id, step)` and
  `UserRepository.consumeRecoveryCode(id, codeHash)` (both atomic, both optional for now — without
  them a non-atomic fallback is used and a startup warning is logged). The built-in Mongo adapter
  implements both; users get an `mfaLastTotpStep` field.
- **Password login on a passwordless account returned 500** (bcrypt threw on the missing hash),
  revealing which accounts are SSO/magic-link only. `verifyPassword` now returns false (after the
  same dummy work) for an account without a password.

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
