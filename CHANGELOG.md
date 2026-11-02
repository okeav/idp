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
  magic link, or through SSO — the attacker's password worked. And with the order reversed, an
  attacker who re-registered right after the victim got the newest email in the victim's inbox to
  activate the attacker's password. Now each verification code is bound to the password of the
  registration that sent it; once an address has been registered more than once before verification,
  `/register/verify-email` also needs that password (`{ email, code, password }`; without it, or
  with the wrong one, 400 `REGISTRATION_PASSWORD_REQUIRED` and the code stays usable), so the inbox
  owner activates their own password and another registration's code is useless to them. Login on a
  pending account answers 401 `INVALID_CREDENTIALS` whatever the password (a distinct "pending"
  answer told the planted password's owner when someone else registered). The stored HMAC of a code
  is no longer accepted as the code (the pre-0.4.0 plain-text fallback applies to 6 digits only).
  Activation by magic link or SSO discards any password (and MFA state) set before the address was
  proven. SSO never attaches a login method to a locked/suspended/deleted account. **Upgrade:** let
  your verify-email page send the password when it gets `REGISTRATION_PASSWORD_REQUIRED`; don't rely
  on login answering `PENDING_VERIFICATION`.
- **Account-takeover races around activation (High).** A repeat registration that read the account
  as pending could still write its password after the owner had activated it (verify-email, magic
  link, SSO, reset) — onto a live account. Re-registration and every activation now write only
  while the account is still pending, in one conditional update (new required
  `UserRepository.updateByIdIfStatus(id, status, patch)`); a repeat registration that loses the race
  changes nothing. A completed **password reset on a never-verified account now activates it**
  (status `ACTIVE`, `registrationContested: false`, MFA state cleared) and deletes its
  email-verification codes — it
  proved the inbox, and a pre-registration's code could otherwise later activate the attacker's
  password over the one just set. verify-email reads the code (new required
  `VerificationTokenRepository.findActive`), checks the contested password, and only then consumes
  it — a refused attempt no longer consumes and re-creates the row, and of two concurrent requests
  with one code only one succeeds. **Upgrade (custom storage adapters):** implement
  `updateByIdIfStatus` and `findActive`.
- **SSO login CSRF, no PKCE, no nonce (Medium).** The SSO `state` was only a cache key, so an
  attacker could start a login with their own provider account and have a victim's browser finish
  it, signing the victim into the attacker's account. `GET /sso/:provider` now also sets a
  per-attempt httpOnly binding cookie (SameSite=Lax; SameSite=None;Secure for Apple's form POST),
  and the callback completes only with it. The state is consumed atomically and checked *before*
  anything else, including a provider `error` (which is no longer reflected — the callback redirects
  with `error=provider_error`). Google, Microsoft and GitHub exchanges use PKCE (S256); Apple's
  `id_token` must carry this login's `nonce` and the right `iss`/`aud`/`exp`. **Upgrade:** mount
  `cookie-parser` before the router (already needed for cookie sessions).
- **Claims were frozen at login.** `/refresh` copied the login-time `claims` forward, so a demotion
  in your app took effect only at the user's next full login — which a refreshing session never
  needs. `session.reresolveClaimsOnRefresh` now defaults to **true** (`resolveAuthContext` runs on
  every refresh). **Upgrade:** set it false to keep the old behaviour; make sure your hook is fast.
- **Enabling MFA now signs out the account's other sessions** (keeping the one that enrolled):
  any of them could be the reason the user is securing the account. `SessionRepository.revokeAllForUser`
  takes `{ exceptJti }`. It also writes the sign-out watermark (`sessionsRevokedAt`) with the
  enrolling session's family exempt (new user field `sessionsRevokedExceptFamily`), so a refresh of
  another session that was already in flight is caught too. **Upgrade (custom storage adapters):**
  persist `sessionsRevokedExceptFamily`, and return `familyId` from `findByJti` (it identifies the
  enrolling session's family — without it the enrolling session is signed out at its next refresh).
- **Magic links.** Requests are limited per address as well as per IP
  (`rateLimiting.magicLinkByEmail`), and requesting a link replaces the earlier one — atomically,
  so concurrent requests can't leave several live links (see "Password reset hygiene").
- **`openid` was granted to every client** whatever its `allowedScopes`; it now must be listed like
  any other scope (the default `allowedScopes` include it).
- **Smaller fixes.** MFA encryption keys must be exactly the base64 of 32 bytes (trailing garbage
  used to be ignored silently); a custom `mfa.secretCipher` whose output looks like a bare base32
  string (and so would be read back as a plain-text secret) is refused; a malformed session id at
  `DELETE /me/sessions/:id` is a 404 and a JSON-typed (`j:`) cookie is ignored (both were 500s);
  `.gitignore` covers `.env.*`. `verifyAccessToken` is documented as not checking revocation (use
  `authContextMiddleware` for that), and service-token `scopes` as caller-asserted.
- **Cookie-authenticated requests had no CSRF defence beyond SameSite (Medium).** `SameSite=Lax`
  stops cross-*site* requests, but not ones from a sibling subdomain, and none at all under
  `cookies.sameSite: 'none'`. A state-changing request whose credential is the session cookie must
  now come from the issuer's origin or one of `cookies.trustedOrigins` (or be `Sec-Fetch-Site:
  same-origin`); otherwise 403 `CSRF_ORIGIN_REJECTED`. Requests without `Origin`/`Sec-Fetch-Site`
  (non-browser clients) and Bearer-authenticated requests are unaffected. The endpoints that *set*
  or clear session cookies — `/login`, `/refresh`, `/logout`, `/mfa/verify`, `/magic-link/verify`,
  `/webauthn/authentication/verify`, `/webauthn/mfa/verify` — apply the same check to every browser
  request, body token or not (login CSRF: a form on a sibling origin signing the victim into the
  attacker's account; logout CSRF: a cross-site form clearing the victim's session). **Upgrade:** list your frontends'
  origins in `cookies.trustedOrigins` (`IDP_COOKIE_TRUSTED_ORIGINS`) if they call these endpoints
  from another origin, cookies or not.
- **Cookie tossing (Medium).** A sibling subdomain (or a script on one) could set an `access_token`
  / `refresh_token` cookie for the parent domain; the browser sends both, the planted one first, and
  the IdP read the attacker's session — signing the victim (or an OAuth2 consent) into the
  attacker's account. Session cookies are now **`__Host-access_token` / `__Host-refresh_token`**
  (host-only, Secure, `Path=/` — only this exact host can set them). With `cookies.domain` (cookies
  shared across subdomains) `__Host-` is impossible: they are `__Secure-…`, and a request carrying
  a session cookie twice is refused with 400 `COOKIE_CONFLICT` (names compared the way the parser
  reads them — trimmed, up to the first `=` — so `name =x; name=y` is a duplicate). Without Secure (`NODE_ENV=development`
  or `cookies.secure: false`) the plain names remain. The SSO binding cookie is always host-only
  (`cookies.domain` no longer applies to it), `__Host-idp_sso_…` when Secure. An `Authorization:
  Bearer` header now wins over the access-token cookie, and a refresh token in the body over the
  refresh cookie (both used to prefer the cookie). Startup validates `cookies.sameSite` (`'lax'`,
  `'strict'` or `'none'`, case-insensitive — a typo used to surface as a 500 on every login), refuses `'none'` without
  Secure cookies, and requires `cookies.trustedOrigins` to be exact origins (no path, no trailing
  slash; the host's case is normalised). **Upgrade:** the old cookies are no longer read, so **every browser user signs in once**
  after deploying; update anything that names the cookies (proxies, tests, a frontend checking for
  `access_token` — it's `httpOnly` anyway; call `GET /me`); fix any `trustedOrigins` entry with a
  path or trailing slash.
- **Errors leaked internals.** The error handler shown in the README echoed every error's message
  — database errors naming collections, indexes and values; body-parser errors echoing the request
  body — and `IdpError` had no `status`, so Express's default handler answered 500 for every
  401/429. `IdpError` now carries `status`/`statusCode`/`expose`, and the new `idpErrorHandler()`
  export answers `{ error, message }` for client errors and a bare `{ error: 'INTERNAL_ERROR' }` (logged)
  for everything else, with fixed messages for malformed or oversized bodies. `POST /refresh` now
  validates its body (a non-string token was a 500). `idpErrorHandler()` without a `logger` logs
  through the one given to `initIdentityProvider` (5xx errors used to be dropped silently).
  **Upgrade:** mount `idpErrorHandler()` after the router, or apply the same rule in your own
  handler.
- **Logs carried tokens.** Error and rejection logs recorded `req.originalUrl`, query string
  included — end-session's `id_token_hint`, an SSO callback's `code`. They now record `req.path`
  only. A throwing hook is logged by its error's `name` and `message` only (an HTTP client's error
  often embeds the request — here, the reset token or magic link being mailed).
- **Token-bearing responses were cacheable.** Every response from the router is now
  `Cache-Control: no-store`, except the public documents: JWKS and `/keys/:kid` (`public,
  max-age=300`), discovery (`ttls.discoveryCache`, default 3600 s) and the services JWKS (60 s).
- **Self-registration could write `metadata`.** `POST /register` stored a user-supplied object on
  the account and handed it to `resolveAuthContext` — any app that kept a role or tenant there
  granted it to whoever registered. It is now ignored unless `registration.acceptMetadata: true`.
  **Upgrade:** set that only if you treat the field as untrusted.
- **bcrypt silently truncated long passwords** at 72 bytes, so two passwords sharing that prefix
  both worked. Passwords over 72 bytes (UTF-8) are now refused at register, reset and change.
- **Profile fields.** `avatarUrl` (released as the ID token's `picture`) must be `https` —
  `javascript:` and `data:` URLs were accepted; `locale` and `zoneinfo` must be well-formed.
- **The refresh token can be kept out of JSON bodies.** With `cookies.refreshTokenInBody: false`
  (`IDP_COOKIE_REFRESH_TOKEN_IN_BODY`) it lives only in its httpOnly cookie, out of reach of page
  script. Recommended for browser-only apps.
- **Dependencies.** `zod` floor raised to `^4.6.7` (GHSA-mrhx-c7xc-m3w5, memory exhaustion); the
  Express peer range is `^4.21.2 || ^5.1.0`. The lockfile is audit-clean; run `npm audit` in your
  app too — `proxy-addr` ≤ 2.0.7 (IP spoofing through `trust proxy` subnets), `body-parser` and `qs`
  had advisories, all fixed by updating within Express's own ranges.
- **Examples and dev files.** The quickstart uses its public dev fallbacks (secrets, MFA key,
  ephemeral signing key) **only with `NODE_ENV=development` set explicitly** — an unset `NODE_ENV`,
  common in containers, counts as production and the quickstart refuses to start until every value
  is set — and uses `idpErrorHandler()`. The root `.env.example` no longer sets
  `NODE_ENV=development` (which turned off secure cookies for anyone copying it) and documents every
  new variable; the quickstart's own `.env.example` sets it, since that's what enables its
  fallbacks. `docker-compose.yml` binds Mongo and Redis (both without auth) to 127.0.0.1 —
  Docker-published ports bypass host firewalls, and the e2e test harness (which hands out any
  user's reset and verification tokens) listens on 127.0.0.1 only. **Upgrade:** if you start from
  the quickstart, keep `NODE_ENV=development` in its `.env` locally and set every secret elsewhere.
- **`configFromEnv` silently turned protections off (Medium).** Only the exact string `"true"` was
  true, so `IDP_COOKIE_SECURE=` (blank), `=1` or `=TRUE` meant insecure cookies (likewise rate
  limiting, per-request session checks), and a non-numeric `IDP_MAX_FAILED_LOGIN_ATTEMPTS` became
  `NaN`, disabling account lockout. Booleans now accept true/false, 1/0, yes/no, on/off (any case);
  a blank variable means the default; anything unrecognised fails startup. New variables:
  `IDP_SSO_BASE_CALLBACK_URL`, `IDP_SSO_ALLOWED_REDIRECT_ORIGINS`, `IDP_SSO_MICROSOFT_TRUST_EMAIL`,
  `IDP_S2S_BOOTSTRAP_SECRETS` (`name=secret,…`), `IDP_S2S_OWN_SERVICE_NAME`, `IDP_REDIS_USERNAME`,
  `IDP_REDIS_TLS`. `IDP_SSO_APPLE_PRIVATE_KEY_B64` is now base64-decoded into the PEM (it was
  passed through still encoded, so Apple sign-in couldn't sign its client secret).
- **Weak configuration was accepted at startup.** `initIdentityProvider()` now refuses:
  `emailHashPepper`/`tokenHashSecret` under 32 characters; `bcryptRounds` outside 10–15
  (`security.allowWeakBcryptRounds` allows ≥ 4, for tests); non-integer lockout settings and
  rate-limit rules; signing keys that aren't RSA, are under 2048 bits, are unparseable, have an unknown
  status, or whose private key doesn't match the public key; and a key set with nothing to sign with.
  It also refuses: an `issuer` that isn't `https` (`http` only for `localhost`, `127.0.0.1`,
  `[::1]`, or anywhere with `NODE_ENV=development` — the issuer is also the default trusted CSRF
  origin, and a non-URL one contributed none); with SSO configured, a plain-`http`
  `sso.baseCallbackUrl` (same exceptions — provider codes are returned to it); any `ttls.*` that isn't a positive integer of seconds; `tokenHashSecret` equal to
  `emailHashPepper`; and, with `session.verifyOnEachRequest: false`, `ttls.revocationCache` shorter
  than `ttls.accessToken` (a revocation marker expiring before its token brings the token back). It
  warns about a remote Redis (`cache` or `rateLimiting`) without `tls`. **Upgrade:** check your
  secrets, keys, issuer, callback URL and `ttls` meet these before deploying.
- **Unbounded in-memory stores.** `MemoryCacheAdapter` holds at most `maxEntries` (100k; expired
  then oldest evicted); `MemoryRateLimiter` at most `maxKeys` (500k) — when full it evicts the oldest
  counters that haven't reached their limit (never an exhausted one, which would release a block),
  and refuses a new key (503 at fail-closed sites) only if every counter is exhausted. Refusing new
  keys outright let a flood of distinct keys deny every new client.
- **Rate-limit keys.** IPv6 clients are keyed by their /64 (one host is routinely given a whole
  /64, which made per-IP limits per *address* meaningless); IPv4-mapped addresses as IPv4.
  Per-address keys use the email's keyed hash instead of the plain address, so Redis and logs no
  longer hold emails. **Note:** `req.ip` is only as trustworthy as Express's `trust proxy` — set it
  to your proxy hop count or subnet, never `true`.
- **Redis.** The rate-limit script sets an expiry whenever a key has none (a failed `EXPIRE` could
  leave a key — and its owner — limited forever) and rounds windows to whole seconds. Both Redis
  adapters accept `username` and `tls`; the limiter no longer silently connects to localhost when
  configured for Redis without a host.
- **Every email lookup scanned the user collection** (the legacy `email` branch of the lookup's
  `$or` had no index). `email` is now indexed.
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
  limited (`rateLimiting.serviceKeyRegistration`). The shared secret cannot register a name listed in
  `bootstrapSecrets` at all (403) — once that service's key was revoked, it could otherwise claim the
  name. A revoked key stays revoked: re-registering it (as every service does at boot) answers 409
  `SERVICE_KEY_REVOKED` instead of re-activating it. A rotated-away key verifies only for
  `serviceMesh.rotationGraceSeconds` (default 3600), not until some later rotation retires it.
  Rotation registers the new key **first** and then demotes the old ones, each only from the status
  it read (`setStatusByKid(kid, status, { expectedStatus })`) — a refused registration demotes
  nothing, and a key revoked mid-rotation stays revoked instead of coming back as ROTATING.
  Concurrent first registrations of one new name with the shared secret (each saw "no key yet")
  now leave exactly one key: the earliest `registeredAt` (then lowest `kid`) keeps the name — the
  Mongo adapter takes `registeredAt` from the database clock (`$$NOW`), so it's the first one
  inserted — the others revoke their own key and answer 409 `SERVICE_NAME_TAKEN`. `bootstrapSecret`, every
  `bootstrapSecrets` value and `sharedSecret` must be at least 32 characters (checked at startup),
  and no per-service secret may equal the shared one. `initServiceIdentity` and
  `remoteJwksKeyLookup` / `verifyServiceTokenRemote` refuse a plain-`http` IdP URL (except
  localhost, or with `NODE_ENV=development` — e.g. a docker-compose service name): the bootstrap secret is sent there, and its key set decides whose tokens are trusted.
  **Upgrade:** prefer `bootstrapSecrets`; lengthen any secret under 32 characters; use an `https`
  IdP URL; a service whose key was revoked must generate a new pair. Custom storage: `upsertByKid`
  must return null for a REVOKED kid; `setStatusByKid` should record `statusChangedAt` and honour
  `{ expectedStatus }` atomically; optional `findByKid`.
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
  had no rate limit and no attempt limit, against a code valid for 24 hours. Wrong 6-digit codes now
  count per **address** (`security.verificationCodeLockout`, default 5 per hour, then locked 15
  min), counted for unknown and already-verified addresses too, so a lock says nothing about
  whether a pending registration exists. The attempt that exhausts the budget clears the codes of
  every outstanding row (new required `VerificationTokenRepository.clearCodes`) and further code
  attempts get 429 `VERIFICATION_LOCKED` — but the emailed **link** keeps working: its 256-bit
  token can't be guessed, so it has no budget, and the owner can still verify while someone
  hammers the code. Attempts are counted *before* the code is checked, so a concurrent burst gets
  no more guesses than the budget. Codes are now stored as HMACs (codes issued before 0.4.0,
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
  storage method `SessionRepository.revokeForClient(clientId, { userId? })`. `client_credentials`
  tokens (every token classified `oauth2-client`, not only those with `gty`), which have no session,
  are checked against their client on every `authContextMiddleware` request: a deactivated (or deleted) client's machine tokens get 401 `TOKEN_REVOKED` at once.
- **Client lifetimes and links were unbounded.** `PATCH /oauth2/clients/:id` caps `accessTokenTTL`
  and `idTokenTTL` at 86400 s (24 h) and `refreshTokenTTL` at one year — an access token can't be
  revoked once issued, so a ten-year TTL was a ten-year credential; the same caps are applied at
  issuance, covering values stored before — and requires `logoUrl`,
  `websiteUrl`, `privacyPolicyUrl` and `termsOfServiceUrl` to be `https` (they're links on the
  consent screen; a `javascript:` URL there ran in the IdP's origin).
- **`GET /oidc/end-session` signed the user out everywhere on any token it was shown.** Any ID
  token (handed to every relying party), and even the pre-MFA challenge token, made it revoke all of
  the user's sessions — via a GET any site can trigger. The hint must now be an ID token. It ends
  the browser's own IdP session if its cookie came with the request (cookies are cleared), and the
  hinted client's sessions for that user **only together with that user's own session** — a hint
  alone ends nothing (ID tokens travel through URLs and logs; holding one must not sign its user out
  of the relying party). Expired hints are accepted, per the spec. There is still no confirmation
  step (see "Known limitations" below).
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
  re-checks it after writing its successor. So does a **login**: it records when its credential
  check began, and if a password reset or logout-all landed while it was in flight, the session it
  just created is revoked and it answers 401 `TOKEN_REVOKED`; the OAuth2 code grant checks the same
  watermark after creating its session.
- **Sessions raced their own revocation (Medium).** An authorization code now records the session
  that authorized it (`sessionJti`, the access token's `jti`) and is refused (`INVALID_GRANT`) if
  that session was signed out before redemption — a sign-out landing while `/authorize` was in
  flight no longer leaves a working code. An ordinary refresh of that session doesn't void the code
  (a rotated row whose family is still live — new required `SessionRepository.isFamilyLive`;
  `findByJti` also returns `revokeReason`), and a sessionless token (the `issueAccessToken()`
  export) binds no session. Reuse detection tombstones the **whole** family (`familyRevokedAt`
  on every row, live or not) and flags a replayed code (`reuseDetectedAt`); a refresh or code
  redemption checks both after inserting its row, so a legitimate request racing the replay can't
  keep a live successor. **Upgrade (custom storage adapters):** implement the new required
  `SessionRepository.isFamilyRevoked(familyId)` and `isFamilyLive(familyId)` and make `revokeFamily` set `familyRevokedAt` on
  every row of the family; persist `sessionJti` on authorization codes; optional
  `AuthorizationCodeRepository.markReused(hash)` sets `reuseDetectedAt` (returned by
  `findUsedByCodeHash`).
- **The `onNewDeviceLogin` alert never fired:** the check ran after the login's own session row was
  written, so the device was always "known". It now runs before.
- **Five anonymous wrong passwords locked an account out of everything (High).** The failed-password
  lockout set the account's status to LOCKED, which refresh, magic link, passkeys, SSO, MFA and the
  OAuth2 grants all refused — and `/refresh` burned the session's token before refusing. An account
  with no password (SSO / magic link only) stayed locked for good, since only a password login lifted
  it. The lockout is now a property of password login only; the status stays ACTIVE and every other
  method and existing sessions keep working. It is counted in the attempt-counter store, not on the
  user (`failedLoginAttempts` / `lockUntil` are no longer set), and only for active accounts that
  have a password (nothing to guess otherwise — no lock, no `onSuspiciousActivityDetected` mail an
  attacker could trigger at will): `password-login:<userId>`,
  `security.maxFailedLoginAttempts` wrong passwords per `security.accountLockDurationMs` window,
  then locked for `accountLockDurationMs`. Each attempt is counted **before** bcrypt runs — 0.3.0
  counted after a failure, so a concurrent burst had every guess checked — and a counter backend
  error fails the login closed (500). A correct password resets the count; other sign-in methods no
  longer do (signing in by magic link mustn't hand a guesser a fresh budget); a password reset does.
  Rows locked before 0.4.0 (status LOCKED with a `lockUntil`) are honoured until `lockUntil`,
  treated as ACTIVE meanwhile (also in `GET /me`'s `status`/`isActive`) and normalised on the next
  sign-in; a LOCKED status *without* `lockUntil` is an administrative lock and still blocks every
  method (a password reset no longer lifts it). **Upgrade:** with an `attemptCounterRepository`
  shared by every instance (custom adapters: see "Storage"), the lockout holds across instances;
  `UserRepository.incrementFailedLoginAttempts` is no longer called.
- **A locked account told right passwords from wrong ones** (423 vs 401), turning the lockout into
  an oracle. While locked, every password gets the same 401 `INVALID_CREDENTIALS`; a password reset
  lifts the lock.
- **A failed refresh burned the refresh token.** `/refresh` and the OAuth2 refresh grant consumed the
  token first, so any refusal or error after that (an inactive account, a throwing
  `resolveAuthContext`) destroyed it, and the client's retry was then treated as token reuse. All
  checks now run before the atomic consume.
- **`/password/change` was an unlimited password oracle (Medium)** for anyone holding a stolen access
  token. Wrong current passwords now count against `security.passwordChangeLockout` (5 per hour,
  locked an hour); the attempt that exhausts it, and every one while locked, answers 429
  `PASSWORD_CHANGE_LOCKED`.
- **Login timing told which emails exist.** The dummy bcrypt hash compared for unknown (and
  passwordless) accounts had a fixed cost of 12, so with any other `bcryptRounds` an unknown email was
  measurably faster or slower. It is now generated at startup with the configured cost, and an
  attempt refused by the password-login lockout before its password was checked still spends a
  bcrypt compare. `/password/forgot` and `/register/resend-verification` now answer before looking
  anything up (the lookup and writes for a real account were measurable too).
- **An authorization code outlived the sessions and the consent it came from (Medium).** A code
  minted shortly before "sign out everywhere" (logout-all, password reset/change, account deletion)
  or before the user withdrew consent — e.g. with a stolen token — still turned into a fresh
  long-lived OAuth2 session. Such codes are now refused with `INVALID_GRANT`.
- **Password reset hygiene.** A new reset request replaces the earlier link — atomically, so
  concurrent requests can't leave several live links (new required
  `VerificationTokenRepository.replaceForUser`, backed in Mongo by the partial unique index
  `one_link_per_user` on `{ kind, user }` for `password_reset` and `magic_link`) — a completed
  reset invalidates every outstanding one, deleted accounts are not sent links, and requests are
  limited per address as well as per IP (`rateLimiting.passwordResetByEmail`). The Mongo adapter now
  builds its indexes at startup (`Model.init()`) and a failed build **fails the boot** rather than
  running without the guarantee. **Upgrade:** on an existing Mongo database the build fails if a
  user already has two reset (or two magic-link) rows left by 0.3.x — delete such duplicates first; custom adapters implement
  `replaceForUser` with an equivalent unique constraint.
- Storage interface (optional for now, with graceful degradation): `SessionRepository.revokeFamily`,
  `revokeForClient`, `AuthorizationCodeRepository.findUsedByCodeHash` and `markReused`;
  `revokeByRefreshTokenHash` takes `{ reason }`. Session rows gain `kind`, `authTime`, `familyId`,
  `familyCreatedAt`, `familyRevokedAt`; authorization codes `sessionJti`, `reuseDetectedAt`; users
  `sessionsRevokedExceptFamily`. **Required, with no fallback** (custom adapters fail without
  them): `UserRepository.updateByIdIfStatus`, `SessionRepository.isFamilyRevoked` and `isFamilyLive`,
  `VerificationTokenRepository.findActive`, `clearCodes` and `replaceForUser` (with a unique
  constraint on one live `password_reset` / `magic_link` per user); `ServiceKeyRepository
  .setStatusByKid` takes `{ expectedStatus }`. See `docs/api/repository-adapters.md`.
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
  one atomic conditional update.
- **Recovery codes were 48 bits (Medium).** With the database and the HMAC key, every user's codes
  fell to one offline search. They are now 20 characters of Crockford base32 — 100 bits — shown as
  `XXXXX-XXXXX-XXXXX-XXXXX`, and hashed bound to the user (HMAC of `mfa-recovery:<userId>:<code>`),
  so one guess can't be tested against everyone's codes at once. Typing is forgiving: any case,
  spaces and dashes optional, `O` read as `0` and `I`/`L` as `1`. **Upgrade:** recovery codes issued
  before 0.4.0 no longer verify — ask users with MFA to regenerate them
  (`POST /me/mfa/recovery-codes`); update any UI that validates the old `XXXXXX-XXXXXX` shape.
- **MFA challenge tokens weren't pinned to this IdP.** They now carry `aud` =
  `<issuer>#mfa-challenge`, and verification requires that audience and the issuer — a challenge
  from another environment sharing a signing key, or any other token type, is refused.
- **`POST /me/mfa/recovery-codes` needed only the password** — anyone with a session and the
  password could mint fresh second factors. It now also requires a current TOTP `code`.
  **Upgrade:** send `{ password, code }`.
- **Passwordless accounts could not disable MFA or regenerate recovery codes** (both demanded a
  password the account doesn't have). `password` is now required only when the account has one.
- Wrong MFA codes no longer also count toward the *password* lockout; the MFA lockout has its own
  counter.
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
- `ERROR_CODES` now lists `COOKIE_CONFLICT`, `REGISTRATION_PASSWORD_REQUIRED`,
  `PASSWORD_CHANGE_LOCKED` and `SERVICE_KEY_REVOKED`. `GET /me` reports the effective status (a
  pre-0.4.0 automatic lock reads `ACTIVE`, as everywhere else).
- **Password login on a passwordless account returned 500** (bcrypt threw on the missing hash),
  revealing which accounts are SSO/magic-link only. `verifyPassword` now returns false (after the
  same dummy work) for an account without a password.

### Known limitations

Deliberately not changed in this release (see README, "Known limitations"):

- `security.tokenHashSecret` can't be rotated without invalidating every stored token and code hash
  and every HMAC-stored OAuth2 client secret, and one key serves all those purposes (no per-purpose
  key derivation).
- Revocation watermarks (`sessionsRevokedAt`) and code/consent timestamps come from each app
  server's clock — keep the servers NTP-synced.
- `prompt` and `max_age` are ignored at `/oauth2/authorize`; the ID token carries `auth_time` for
  relying parties to enforce.
- `mfa.requireEncrypted` still defaults to `false` — set it `true` after `migrateMfaSecrets()`.
- `cookies.refreshTokenInBody` still defaults to `true` — set it `false` for browser-only apps.
- The refresh cookie is `Path=/` (required by the `__Host-` prefix), so it accompanies every request
  to the IdP's host.
- `GET /oidc/end-session` has no confirmation step.

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
