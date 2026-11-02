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
    // verificationCode is null once the address has had 3 codes this code lifetime — always send the link.
    onVerificationEmailRequested: async ({ email, verificationToken, verificationCode }) => {
      const link = `https://app.example.com/verify-email?email=${encodeURIComponent(email)}&token=${encodeURIComponent(verificationToken)}`;
      await sendEmail(email, verificationCode ? `Your code is ${verificationCode} — or open ${link}` : `Open ${link} to verify your address`);
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

1. **Startup validation.** `initIdentityProvider()` now refuses `emailHashPepper`/`tokenHashSecret` under 32 characters, `bcryptRounds` outside 10–15, non-RSA or < 2048-bit signing keys (or a private key that doesn't match its public key), webhook endpoints that aren't `https` or whose secret is under 16 characters, and — with any SSO provider configured — a missing `sso.allowedRedirectOrigins` or `sso.baseCallbackUrl`. It also refuses a non-`https` `issuer` or `sso.baseCallbackUrl` (`http` only for `localhost`/`127.0.0.1`/`[::1]`, or anywhere with `NODE_ENV=development`), any `ttls.*` that isn't a positive whole number of seconds, `tokenHashSecret` equal to `emailHashPepper`, `ttls.revocationCache` shorter than `ttls.accessToken` when `session.verifyOnEachRequest` is `false`, an invalid `cookies.sameSite` (case-insensitive; or `'none'` without Secure cookies), `cookies.trustedOrigins` entries that aren't exact origins, and service-mesh secrets (`bootstrapSecret`, each `bootstrapSecrets` value, `sharedSecret`) under 32 characters or a per-service secret equal to the shared one. Remote Redis without `tls` gets a startup warning. `configFromEnv()` parses strictly: booleans accept true/false, 1/0, yes/no, on/off; anything unrecognised fails startup.
2. **Access tokens are first-party only by default.** `authContextMiddleware`/`verifyAccessToken` accept only tokens this IdP issued for itself. A resource server that accepts OAuth2 tokens opts in with `authContextMiddleware({ accept: ['oauth2-user'] })` and checks `req.auth.scopes`; a first-party token minted with a custom `audience` needs `authContextMiddleware({ audience })`.
3. **Errors.** Mount `idpErrorHandler()` after the router instead of a handler that echoes `err.message` (the one this README used to show leaked database and body-parser internals).
4. **CSRF.** Cookie-authenticated state-changing requests — and every browser request to the endpoints that set or clear session cookies (`/login`, `/session/refresh`, `/session/logout`, `/mfa/verify`, `/magic-link/verify`, `/webauthn/authentication/verify`, `/webauthn/mfa/verify`), cookies or not — must come from the issuer's origin or `cookies.trustedOrigins` (`IDP_COOKIE_TRUSTED_ORIGINS`) — list your frontends' origins.
5. **Frontend flows.** Registration of an address that is still pending binds each verification code to its registration's password; once an address has been registered twice, `/register/verify-email` answers 400 `REGISTRATION_PASSWORD_REQUIRED` until the page also sends that `password` (a wrong password answers 400 `INVALID_OR_EXPIRED_TOKEN`, like a wrong code). Password login on a pending account answers 401 `INVALID_CREDENTIALS` (not 403 `PENDING_VERIFICATION`). `/register` and `/register/resend-verification` now answer `{ status: 'ok', verificationTicket }` and set a `__Host-verification_ticket` cookie; wrong 6-digit codes are budgeted per ticket (a browser that keeps the cookie needs no change; a client without cookies sends the ticket as `ticket` to `/register/verify-email`), and attempts without one share a per-address budget (`security.verificationCodeLockout`, now 5 per 24 h with a 24 h lock, 429 `VERIFICATION_LOCKED`), with a year-long cap of `maxTotalFailedAttempts` (20) wrong codes per address that anyone can spend — a spent budget no longer clears the codes, and the emailed link always works. **Verification emails must include the link:** at most 3 codes are issued per address per code lifetime, and later emails get `verificationCode: null` in `onVerificationEmailRequested`. A completed password reset now also verifies a pending account. Too many wrong passwords now lock password login only (active accounts with a password; counted in the attempt counter, `password-login:<userId>`; the user's `lockUntil` is no longer set) — the account stays `ACTIVE`, every other method keeps working, and only a password reset or the lock's expiry lifts it; `ACCOUNT_LOCKED` (423) means an administrative lock (status `LOCKED` without `lockUntil`), which a password reset no longer lifts. `/password/change` answers 429 `PASSWORD_CHANGE_LOCKED` after too many wrong current passwords. Magic-link verify and the SSO callback now stop at the MFA challenge for MFA accounts; OAuth2 consent pages post the `consent_challenge` they received; every OAuth2 client sends PKCE (`S256`); `POST /me/mfa/recovery-codes` takes `{ password, code }`; recovery codes are now `XXXXX-XXXXX-XXXXX-XXXXX` (100 bits, Crockford base32) and **codes issued before 0.4.0 no longer work** — users with MFA should regenerate them; passkey registration, MFA enrolment and account deletion answer 401 `REAUTHENTICATION_REQUIRED` unless the user logged in within the last 15 minutes.
6. **Session cookies and routes.** The cookies are now `__Host-access_token` (`Path=/`), `__Secure-refresh_token` (`Path=<mount path>/session`) and `__Host-refresh_binding` (`Path=/`, a keyed hash of the refresh token — a refresh cookie value without a matching binding is ignored; `cookies.sessionPath` pins the refresh cookie's path); with `cookies.domain`, `__Secure-access_token` and `__Secure-refresh_binding`; without Secure (`NODE_ENV=development` or `cookies.secure: false`), the plain names. Everything that reads the refresh cookie **moved under `/session`**: `POST /refresh` → `/session/refresh`, `POST /logout` → `/session/logout`, `POST /logout/all` → `/session/logout/all`, `GET|POST /oidc/end-session` → `/session/end` (discovery's `end_session_endpoint` follows). Update your frontend's calls, and any proxy rule, CDN path or relying party that names the old paths. Existing cookies are no longer read, so **every browser user signs in once** after the upgrade. Update anything that refers to the cookies by name (proxies, tests, a frontend that checks for the cookie — they're `httpOnly`, so use `GET /me`). An `Authorization: Bearer` header now wins over the cookie, and a refresh token in the body wins over the refresh cookie.
7. **The refresh token is no longer in browser JSON responses.** `cookies.refreshTokenInBody` now defaults to `'auto'`: login, `/session/refresh`, MFA, magic-link and passkey responses include `refreshToken` only for requests without an `Origin` or `Sec-Fetch-Site` header (non-browser clients); a browser gets it only as the httpOnly cookie. A browser app that reads `refreshToken` from the JSON body must set `true` (`IDP_COOKIE_REFRESH_TOKEN_IN_BODY=true`). Current browsers send one of those headers on these POSTs; a very old browser that sends neither gets the token in the body — a browser-only app that must cover such browsers sets `false`.
8. **Stored token hashes changed.** Each stored hash is now keyed per purpose (HKDF from `tokenHashSecret`), so every refresh token and every outstanding email-verification link, reset link and magic link issued by 0.3.x stops working — listing the old secret in `security.previousTokenHashSecrets` doesn't help, since previous secrets are derived the same way. With the cookie rename, every user, browser or not, signs in again (recovery codes were already invalidated, see 5). OAuth2 client secrets stored by 0.3.x are bcrypt and still verify (re-stored on first use).
9. **Claims are re-resolved on refresh** (`session.reresolveClaimsOnRefresh` now defaults to `true`) — keep `resolveAuthContext` fast, or set it `false`.
10. **Webhooks** no longer carry reset tokens, magic-link tokens or verification codes unless the endpoint sets `includeCredentials: true` — set it on the endpoint that sends your emails.
11. **SSO** with Microsoft on the `common` authority can no longer create or link accounts by email; pin `tenant`, or set `trustEmail: true` knowingly.
12. **MFA secrets.** `mfa.requireEncrypted` now defaults to `true` whenever `mfa.encryptionKey` or `mfa.secretCipher` is set, so a plain-text TOTP secret left from ≤ 0.2.x is refused (500 `MFA_SECRET_NOT_ENCRYPTED`): **that user can't complete MFA with a TOTP code or even a recovery code until `migrateMfaSecrets()` has run** (only a passkey second factor still works). Run it before upgrading, or set `requireEncrypted: false` explicitly until you have.
13. **OIDC logout and `prompt`.** `GET /session/end` from a signed-in browser without an `id_token_hint` no longer ends the session; it answers `200 { "action": "logout_confirmation_required" }` — or, with `oidc.endSessionConfirmationUrl` (`IDP_OIDC_END_SESSION_CONFIRMATION_URL`; `https`, on the issuer's origin or a `cookies.trustedOrigins` origin), redirects to that page, forwarding `client_id`, `state`, `ui_locales` and `logout_hint` — and your IdP frontend confirms with the user and `POST`s the same parameters (from a trusted origin). `/oauth2/authorize` now honours `prompt` and `max_age`, and its `login_required` response carries a `reason`. For `prompt=login`, `prompt=select_account` and `max_age` it also carries a single-use `login_challenge`: pass it to the sign-in you run (`login_challenge` in the body of `/login`, `/magic-link/verify` or `/webauthn/authentication/verify`, or the query of `GET /sso/:provider`; MFA carries it through) and add it to the repeated authorize request — a login made without it doesn't satisfy `prompt=login` (`docs/api/oauth2-authorization-server.md`).
14. **Service mesh** defaults to `tokenMode: 'token'`; prefer per-service `serviceMesh.bootstrapSecrets` (the shared secret can no longer register a name listed there). A revoked service key is never re-activated — re-registering it answers 409 `SERVICE_KEY_REVOKED`, so the service must generate a new key pair — and a rotated-away key verifies only for `serviceMesh.rotationGraceSeconds` (default 3600). Service-mesh secrets must be ≥ 32 characters, and `initServiceIdentity` / `verifyServiceTokenRemote` refuse a plain-`http` IdP URL (except localhost, or with `NODE_ENV=development`).
15. **Custom storage adapters** must persist the new session fields (`kind`, `authTime`, `familyId`, `familyCreatedAt`, `familyRevokedAt`, `sessionEpoch`), `sessionEpoch` on users and authorization codes, `consentVersion` on codes and a `version` on consents, and implement the new **required** methods `UserRepository.updateByIdIfStatus` and `bumpSessionEpoch`, `SessionRepository.isFamilyRevoked`, `rotatedWithin` and `raiseFamilyEpoch`, `SessionRepository.findByJti` (now required, returning `familyId`), `VerificationTokenRepository.findActive` and `replaceForUser` (with a unique constraint: one live `password_reset` / `magic_link` row per user — the Mongo adapter's index is `one_link_per_user`; Mongo indexes are now built at startup and a failed build fails the boot, so delete duplicate reset / magic-link rows left by 0.3.x first), `SessionRepository.isFamilyLive`, plus the other new atomic methods — see "Storage" below; `initIdentityProvider()` now refuses an adapter missing any required method, naming each one. `VerificationTokenRepository.clearCodes` is no longer required. Add the optional `databaseTime()` (see 17). Custom cache adapters must add an atomic `take()`. Custom `ServiceKeyRepository`s: `upsertByKid` must return null for a REVOKED kid, `setStatusByKid` should record `statusChangedAt` and honour `{ expectedStatus }`, and `findByKid` is a new optional method.
16. **The quickstart** (`examples/express-quickstart`) uses its public dev fallbacks only with `NODE_ENV=development` set explicitly (its `.env.example` now sets it); otherwise it refuses to start until every secret is set.
17. **Clock skew.** At startup each server compares its clock with the database's (`storage.databaseTime()`; Mongo: `hello.localTime`) and **refuses to start** past `clock.maxSkewSeconds` (default 30; `IDP_CLOCK_MAX_SKEW_SECONDS`), then re-checks every `clock.checkIntervalSeconds` (default 600), logging an error past the maximum and a warning past `clock.warnSkewSeconds` (default 2). Run NTP on your app servers. A custom adapter without `databaseTime()` gets a startup warning and no check. `checkClockSkew()` returns `{ skewMs, ok, level }` for health checks.

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
   `mfa.requireEncrypted: true` (since 0.4.0 the default once a key is set — see "Upgrading from
   0.3.x"). See `docs/api/mfa.md`.
3. **Access tokens die on logout-all / password reset.** `session.verifyOnEachRequest` (default
   `true`) makes `authContextMiddleware` check the token's session row on every request, so
   revocations take effect on every instance immediately. Budget one indexed storage read per
   authenticated request, or set it `false` to keep 0.2.x behaviour (revoked users' access tokens
   live until expiry, up to 1 hour by default). See `docs/api/middleware.md`.

Also new in 0.3.0: a per-account MFA lockout (`mfa.lockout`, 5 failures → 15-minute lock, returning
429 `MFA_LOCKED`), and rate limiting that fails closed on credential checks (see "Rate limiting"
below). Custom storage adapters keep working but should add `sessionRepository.findByJti` (required
since 0.4.0) and `attemptCounterRepository` (see "Storage").

## Configuration

See `.env.example` for the full list of environment variables and `types/index.d.ts` for the `IdpConfig` shape (`docs/api/bootstrap-config.md` documents both, with every default and startup check). Required fields:

- `issuer` — this IDP's URL, used as the JWT `iss` claim. `https` (plain `http` only for localhost, or with `NODE_ENV=development`).
- `mongo.uri` (or `mongo.connection` — an existing Mongoose connection).
- `signingKeys.keys` — at least one `ACTIVE` RS256 keypair (PEM or base64 PEM), RSA ≥ 2048 bits.
- `security.emailHashPepper` — HMAC key for the email blind index; random, at least 32 characters, never rotated.
- `security.tokenHashSecret` — the secret the per-purpose HMAC keys for opaque tokens at rest (refresh tokens, codes, links, recovery codes, client secrets) are derived from; random, at least 32 characters, ≠ `emailHashPepper`. Rotate it by moving the old value into `security.previousTokenHashSecrets` (`IDP_PREVIOUS_TOKEN_HASH_SECRETS`) — see `docs/api/bootstrap-config.md`.
- `mfa.encryptionKey` — exactly the base64 of 32 bytes (`openssl rand -base64 32`); encrypts TOTP secrets at rest (AES-256-GCM). Required while `mfa.enabled` (default `true`); set `mfa.enabled: false` instead if you don't use TOTP. Rotation and KMS-backed ciphers: `docs/api/mfa.md`.
- `sso.allowedRedirectOrigins` and `sso.baseCallbackUrl` — only once any `oauthProviders` entry is configured.

Everything else has a sensible default. RBAC-shaped config (roles, scopes, capabilities) doesn't exist in this schema on purpose — see "Claims are opaque" below.

**`trust proxy`.** Per-IP rate limits key on `req.ip` (IPv6 clients by their /64). Behind a load balancer or reverse proxy, set Express's `trust proxy` to the hop count or the proxies' subnet — never `true`, which lets any client pick its own IP through `X-Forwarded-For`.

### Cache adapter

`config.cache.adapter` is `'memory'` (default) or `'redis'`.

- **memory** — zero config, but single-process only. State (revocation cache, SSO CSRF state, WebAuthn and OAuth2 consent challenges) is lost on restart and not shared across instances. Capped at 100k entries. Fine for local dev or a genuinely single-instance deployment; wrong for anything horizontally scaled.
- **redis** — set `config.cache.adapter = 'redis'` and `config.cache.redis = { host, port, username?, password?, tls? }` (`tls: true` for managed Redis or anything off the local network — startup warns about a remote host without it). Requires `ioredis` as a peer dependency; it's only `import()`-ed when this adapter is actually selected.

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

`req.auth.userId` is `undefined` for `oauth2-client` tokens, and `authContextMiddleware` checks such a token against its client on every request — a deactivated client's machine tokens stop at once (401 `TOKEN_REVOKED`). `verifyAccessToken()` checks signature, issuer, expiry, type and kind/audience — **not** revocation; use `authContextMiddleware` where a logged-out session must stop working. `requireRecentAuth()` (mount after `authContextMiddleware`) answers 401 `REAUTHENTICATION_REQUIRED` unless the user actually logged in within `session.recentAuthMaxAgeSeconds` (default 15 minutes); the router uses it for passkey registration and deletion, MFA enrolment and account deletion. See `docs/api/middleware.md`.

**Cookie sessions and CSRF.** The access-token cookie is `__Host-access_token` (host-only, Secure, `Path=/` — a sibling subdomain can't plant it). The refresh-token cookie, `__Secure-refresh_token`, is scoped to `Path=<mount path>/session` — the only routes that read it (`/session/refresh`, `/session/logout`, `/session/logout/all`, `/session/end`) — so the long-lived token is sent nowhere else; since a path-scoped cookie can't be `__Host-`, the value used is the one whose keyed hash the host-only `__Host-refresh_binding` (`Path=/`) holds, and a sibling subdomain can't plant that binding — a planted refresh cookie is simply ignored. `cookies.sessionPath` pins the path when the router's mount path can be spelled several ways. With `cookies.domain` the cookies are `__Secure-…` domain cookies and a request carrying one twice is refused (400 `COOKIE_CONFLICT`); without Secure (development) they keep their plain names. An `Authorization: Bearer` header wins over the access-token cookie, and a refresh token in the body over the refresh cookie. A state-changing request authenticated by the session cookie must come from the issuer's origin or one of `cookies.trustedOrigins` (exact origins), or it gets 403 `CSRF_ORIGIN_REJECTED`. The endpoints that *set* or clear session cookies — `/login`, `/session/refresh`, `/session/logout`, `/mfa/verify`, `/magic-link/verify`, `/webauthn/authentication/verify`, `/webauthn/mfa/verify` — apply the same check to every browser request (login CSRF; `/session/refresh` checks it before reading any cookie), so a frontend on another origin must be listed even if it doesn't use cookies. `Authorization: Bearer` requests and non-browser clients (no `Origin`/`Sec-Fetch-Site`) are unaffected. The refresh token appears in JSON responses only for non-browser clients by default (`cookies.refreshTokenInBody: 'auto'`); `true` includes it for every request, `false` for none.

### Sessions

Each login starts a refresh-token *family*. `/session/refresh` rotates the token; a rotated token presented again after `session.refreshReuseGraceSeconds` (default 10 s — two tabs refreshing at once) revokes the whole family and emits `REFRESH_TOKEN_REUSE_DETECTED`. A family ends `session.absoluteLifetimeSeconds` (default 90 days) after its login however actively it's refreshed. First-party and OAuth2 refresh tokens are not interchangeable: `/session/refresh` accepts only first-party ones, the OAuth2 `refresh_token` grant only those issued to the calling client (a token presented at the wrong one is revoked). Every check runs before the token is consumed, so a refused refresh doesn't burn it. Enabling MFA signs out the account's other sessions. Races are closed after the fact: a refresh or code redemption re-checks the family's tombstone after inserting its row; every "sign out everywhere" increments the user's `sessionEpoch` before revoking, and a login, refresh or code redemption re-checks it after writing its row (a password reset or logout-all landing mid-login → 401 `TOKEN_REVOKED`); and an authorization code is refused if the session that authorized it was signed out before redemption (an ordinary refresh of that session doesn't void it), or if the consent changed since. These orderings use counters and the database's clock, never a comparison of app servers' clocks. Expiry (token `exp`, code, link and lockout lifetimes) does use each server's clock, so the skew is bounded: each server checks its clock against the database's at startup and every `clock.checkIntervalSeconds`, refusing to start past `clock.maxSkewSeconds` (default 30 s) — see `docs/api/bootstrap-config.md`. See `docs/api/password-email-auth.md`.

### Claims are opaque

`issueAccessToken({ sub, email, claims })` — `claims` is whatever object you pass. It comes back untouched as `req.auth.claims` after `authContextMiddleware`. This package never validates its shape, and ships no scope-matching or permission-checking logic — that's your application's job (or a separate RBAC package).

For login flows that mint a session on your behalf (password login, MFA-verify, SSO callback, magic-link verify, WebAuthn login), configure `hooks.resolveAuthContext(user, ctx)` to build that `claims` object — it's called right before the token is issued and defaults to `() => ({})` if you don't supply one.

Since 0.4.0 `POST /session/refresh` calls `resolveAuthContext(user, { isNewUser: false, method: 'refresh' })` again on every refresh (`config.session.reresolveClaimsOnRefresh`, default `true`), so a role change or suspension in your app takes effect within one access-token TTL. Keep the hook fast — it runs on every refresh. Set `reresolveClaimsOnRefresh: false` to carry the login-time `claims` forward instead; they then stay frozen for the whole session family (up to `session.absoluteLifetimeSeconds`).

The user record has a `metadata` object, but `POST /register` writes it only with `registration.acceptMetadata: true` — and then it's attacker-controlled, so never derive a role or tenant from it. Keep app data in your own collection (`docs/examples/consumer-managed-app-data.md`).

### Event hooks

All hooks are optional, default to no-ops, and are never thrown — a hook that throws is logged and swallowed, never breaks the request it's attached to. Each is awaited for at most `hookTimeoutMs` (default 10 s); after that the request carries on and the hook keeps running. On the endpoints that must not reveal whether an account exists (register, resend verification, forgot password, magic-link request) the email hooks are started but not awaited (resend verification and forgot password respond before even looking the address up) — in serverless runtimes, make them hand off quickly (enqueue rather than send inline).

| Hook | Fires on |
|---|---|
| `onAuditLog(event)` | Every audit-worthy action (login, logout, password change, MFA changes, OAuth2 grants, admin actions, SSO events, refresh-token reuse, etc.) — `event.action` identifies which one. |
| `onVerificationEmailRequested` | Registration (including re-registering a still-pending address) and resend-verification. `verificationCode` is `null` from the address's fourth email in a code lifetime — the template must then send only the link (`verificationToken`). |
| `onPasswordResetRequested` | Forgot-password. |
| `onPasswordChanged` | Password change/reset completed. |
| `onSuspiciousActivityDetected` | Password login locked after too many failed logins (once, when the lock starts). |
| `onNewDeviceLogin` | Login from a browser/OS combination not seen before for this user. |
| `onMagicLinkRequested` | Magic-link login requested — carries the raw token to embed in the emailed link. |
| `resolveAuthContext(user, ctx)` | Password login, MFA-verify, SSO callback, magic-link verify, WebAuthn login — builds the access token's `claims`. Also called on `/session/refresh` while `config.session.reresolveClaimsOnRefresh` is `true` (the default). Not wrapped: a throw fails the login. |

This package never talks to a message bus, SMTP server, or push provider directly — wire your own inside these hooks.

### Rate limiting

Request-rate limiting is enabled by default (`config.rateLimiting.enabled = true`) and is a distinct concern from `security.maxFailedLoginAttempts` (which locks one account's *password login* after N wrong passwords within `security.accountLockDurationMs`, for that long — the account stays `ACTIVE`, so refresh, magic link, passkeys, SSO and existing sessions keep working; signing in another way doesn't reset the count, a password reset does). Rate limiting instead throttles the *rate* of requests to the sensitive endpoints within a fixed window, regardless of whether individual requests succeed:

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

The MFA challenge limit covers both `/mfa/verify` and `/webauthn/mfa/verify`. Separately — and regardless of `rateLimiting.enabled` — per-**account** lockouts are counted in storage (the `attemptCounterRepository`), so they hold across instances and IPs: the password-login lockout (`security.maxFailedLoginAttempts`, default 5 wrong passwords per 30 min → password login locked for 30 min, every password answered 401 `INVALID_CREDENTIALS`; counted before bcrypt runs, failing closed), the MFA lockout (`config.mfa.lockout`, default 5 failed second-factor attempts in 15 min → locked for 15 min, 429 `MFA_LOCKED`), the email-verification **code** budgets (`security.verificationCodeLockout`, default 5 wrong codes per 24 h → 429 `VERIFICATION_LOCKED` for 24 h, never shorter than the code's lifetime — counted per verification ticket, which `/register` and `/register/resend-verification` hand out for the address, and per address for attempts without one, so a stranger's ticketless guesses don't spend the registrant's ticket budget; and at most `maxTotalFailedAttempts` (default 20) wrong codes per address a year in all — anyone's, so a stranger can switch an address to link-only; at most 3 codes are issued per address per code lifetime; codes aren't cleared and the emailed link always works), and the password-change lockout (`security.passwordChangeLockout`, default 5 wrong current passwords per hour → locked for an hour, 429 `PASSWORD_CHANGE_LOCKED`).

Override any rule under `config.rateLimiting.<rule>` — each takes `{ max, windowSeconds }` (positive integers). Set `config.rateLimiting.enabled = false` to disable entirely if you already rate-limit at a gateway/CDN layer (e.g. Cloudflare, an API gateway) covering every one of these endpoints — running it twice is redundant, not harmful, but the extra storage round-trip on every request is pure overhead if a layer in front of this service already enforces it.

Per-IP keys collapse IPv6 addresses to their /64; per-address keys use the email's keyed hash, so Redis and logs never hold email addresses. Uses the same adapter pattern as the cache layer: `config.rateLimiting.adapter` is `'memory'` (default, single-process, capped at 500k keys — when full, the oldest counters that haven't reached their limit are evicted (never an exhausted one), and a new key is refused — failing closed — only if every counter is exhausted) or `'redis'` (shares the cache adapter's Redis connection automatically if `config.cache.adapter` is also `'redis'`, otherwise set `config.rateLimiting.redis` separately — startup fails rather than connecting to an unconfigured localhost).

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

Give each service its own registration credential with `serviceMesh.bootstrapSecrets: { billing: '<secret>', ... }` — it covers only that service's name and lets it rotate its key. The legacy shared `bootstrapSecret` can only register a name that has no key yet (otherwise 409 `SERVICE_NAME_TAKEN`) and never a name listed in `bootstrapSecrets` (403 `FORBIDDEN`). A revoked key stays revoked — registering it again answers 409 `SERVICE_KEY_REVOKED` — and a rotated-away key keeps verifying for `serviceMesh.rotationGraceSeconds` (default 3600) only. `serviceMesh.tokenMode` defaults to `'token'`; `requireServiceCallerMiddleware` refuses shared-secret callers unless `serviceMesh.allowLegacySecretCallers: true`. Service tokens without `exp`, living over 5 minutes, or with `iat` in the future are refused, and `revokeServiceKey(kid)` withdraws a key. See `docs/api/service-mesh.md`.

### SSO / social login

Google, GitHub, Microsoft (Entra ID — defaults to the `common` multitenant endpoint, supporting both work/school and personal Microsoft accounts), Apple, and LinkedIn. Configure whichever you use under `config.oauthProviders`, together with the required `config.sso.allowedRedirectOrigins` (exact origins the browser may be sent back to — `https`, or `http` only for localhost) and an absolute `https` `config.sso.baseCallbackUrl` (`http` only for localhost, or with `NODE_ENV=development`). Mount `cookie-parser` before the router: `GET /sso/:provider` sets a per-attempt binding cookie the callback requires (login-CSRF protection) — always host-only (`__Host-idp_sso_…` when Secure), whatever `cookies.domain` says. Google, Microsoft and GitHub use PKCE; Apple's `id_token` must carry this login's nonce. Provider calls time out after `sso.providerTimeoutMs` (default 10 s).

The callback is a **single step** — it resolves the identity, calls `hooks.resolveAuthContext`, and mints the full session directly. (An earlier two-step "exchange token" design existed in the source this was extracted from, purely because identity resolution and role/permission resolution lived in two different internal services there — not for any redirect-URI or CSRF-security reason. If you need that same split, implement it inside your own `resolveAuthContext`.) For an account with MFA enabled it instead redirects to `redirect_uri` with `#mfa_required=1&mfa_challenge_token=…&expires_in=…` in the fragment and sets no cookies — your frontend completes the challenge.

An account is created or linked by email only when the provider vouches for the address: Google, Apple and LinkedIn must assert `email_verified`, GitHub uses only the account's primary verified address, and Microsoft's address is trusted only when `oauthProviders.microsoft.tenant` names a single tenant (or with an explicit `trustEmail: true`). Otherwise the callback redirects with `error=email_not_verified`; a provider-side error redirects with `error=provider_error`. See `docs/api/sso-social-login.md`.

### Error handling

Every error this package throws on purpose is an `IdpError` (`{ code, httpStatus, status, statusCode, expose, message, cause? }`) passed to `next(err)`. The package never shapes an HTTP response body itself — mount the exported `idpErrorHandler()` after the router:

```js
app.use('/auth', buildRouter());
app.use(idpErrorHandler({ logger })); // logger optional — defaults to the one given to initIdentityProvider
```

It answers an `IdpError` below 500 with `{ error: code, message }`, malformed or oversized bodies with fixed 400/413 messages, and everything else with a bare 500 `{ error: 'INTERNAL_ERROR' }` (logged with `req.path` only — never the query string, which can carry tokens; hook errors are likewise logged by name and message only). If you write your own handler for a different envelope, keep the same rule — never echo the message of a non-`IdpError` (database and body-parser errors carry collection names, values and request bodies). See `ERROR_CODES` and `docs/api/errors.md` for the catalogue of codes you might see.

## Storage

MongoDB is the only concrete storage adapter shipped in this package, behind eight repository interfaces (`UserRepository`, `SessionRepository`, `AuthorizationCodeRepository`, `ConsentRepository`, `OAuthClientRepository`, `VerificationTokenRepository`, `ServiceKeyRepository`, `CredentialRepository` — documented in `src/storage/interfaces.js`). Other adapters (Postgres, DynamoDB, ...) implement the same eight interfaces and plug in through `config.storage.factory`; nothing above the storage layer needs to change.

Optional additions, each with a startup warning and a weaker fallback when missing:

- 0.3.0: an `AttemptCounterRepository` (the lockout counters — MFA, and since 0.4.0 password login, verification codes and tickets, and password change; Mongo stores them in the `IdpAttemptCounter` collection). Without it, the lockouts and verification tickets are counted per instance. (`SessionRepository.findByJti`, optional in 0.3.0, is required since 0.4.0.) `@okeav/idp-core-postgres` 0.2.0 implements both.
- 0.4.0: `UserRepository.claimTotpStep` and `consumeRecoveryCode` (atomic TOTP-replay and recovery-code checks), `SessionRepository.revokeFamily` and `revokeForClient` (refresh-token reuse detection; consent revocation and client deactivation), and `AuthorizationCodeRepository.findUsedByCodeHash` and `markReused` (authorization-code reuse). `revokeAllForUser` takes `{ exceptJti }` and `revokeByRefreshTokenHash` takes `{ reason }`. `ServiceKeyRepository.findByKid` (optional) lets a rotation refuse a revoked key up front. `databaseTime()` on the storage object (the database's clock; Mongo: `hello.localTime`) enables the clock-skew check — without it, a startup warning and no check.

0.4.0 adapters must also implement these **required** methods (no fallback — `initIdentityProvider()` refuses an adapter missing any method in `REQUIRED_STORAGE_METHODS`, naming each): `UserRepository.updateByIdIfStatus(id, status, patch)` (atomic: write only while the status is unchanged) and `bumpSessionEpoch(id, { exceptFamily })` (atomic: increment the user's `sessionEpoch`, resolve the new value), `SessionRepository.findByJti(jti)` (returning `familyId`; optional in 0.3.x), `SessionRepository.rotatedWithin(hash, seconds)` (whether the token was rotated less than `seconds` ago, by the database's clock — `revokeByRefreshTokenHash` must write `revokedAt` from that clock), `raiseFamilyEpoch(familyId, epoch)`, `isFamilyRevoked(familyId)` (with `revokeFamily` tombstoning every row of the family, `familyRevokedAt`) and `isFamilyLive(familyId)` (whether the family has a live row), and `VerificationTokenRepository.findActive` (read without consuming) and `replaceForUser` (one live `password_reset` / `magic_link` per user, atomically — back it with a unique constraint; Mongo: partial unique index `one_link_per_user` on `{ kind, user }`). They must persist the new session fields (`kind`, `authTime`, `familyId`, `familyCreatedAt`, `familyRevokedAt`, `sessionEpoch`), `sessionJti`, `sessionEpoch` and `consentVersion` on authorization codes, a `version` on consents (an integer, incremented by both `upsert` and `revoke`; `upsert` resolves the updated consent), `sessionEpoch` (an integer on every read — 0 for old rows — or sign-in fails closed), `registrationContested` and `sessionsRevokedExceptFamily` on users, `passwordHash` on email-verification tokens and `statusChangedAt` on service keys (`setStatusByKid` records it and honours `{ expectedStatus }`; `upsertByKid` must return null and change nothing for a REVOKED kid), return `familyId` and `revokeReason` from `findByJti`, and implement `CredentialRepository.updateCounter` and `deleteByCredentialId` as conditional writes that resolve whether they changed anything. See `docs/api/repository-adapters.md`.

**Mongo replica set required for transactions.** `SessionRepository.createSessionForLogin()` — the atomic "write session + audit record + update lastLoginAt" used by login/MFA-verify/SSO — uses a real Mongo transaction (`connection.startSession().withTransaction()`), which requires your MongoDB deployment to be a replica set (including a single-node one) or a sharded cluster. A standalone `mongod` cannot run it. Atlas and most managed Mongo offerings are replica sets by default.

`initIdentityProvider()` checks this at **startup** (a real, read-only, no-op transaction) rather than letting it surface as a confusing failure on someone's first login — see `src/storage/mongo/assert-transactions.js`. If your deployment doesn't support transactions, `initIdentityProvider()` throws an `IdpError` (`code: 'MONGO_TRANSACTIONS_UNSUPPORTED'`) with the fix inline: use `docker-compose.yml` in this repo for local dev, or convert an existing standalone `mongod` in place by restarting it with `--replSet rs0` and running `rs.initiate()` once — no reinstall, existing data is preserved. Set `mongo.skipTransactionCheck: true` in config to skip this probe (e.g. a CI job reusing a known-good cluster) and shave the extra round trip off startup.

## Known limitations

The four limitations listed in earlier 0.4.0 builds are resolved: the refresh cookie is scoped to `/session` (with a host-only binding cookie), clock skew is bounded against the database's clock, a stranger can no longer use up the registrant's verification-code attempts, and `prompt=login` needs a login made for that request. What remains:

- **Clock skew is bounded, not eliminated.** Expiry is still compared against each server's clock; the guard keeps every server within `clock.maxSkewSeconds` (default 30 s) of the database, so two servers can disagree by up to twice that. A storage adapter without `databaseTime()` isn't checked at all (startup warning).
- **A stranger can disable the code path for an address.** A registrant who enters the code where the ticket isn't available (another device, cookies cleared) spends the per-address budget, which a stranger who knows the address can use up — the code is then refused there until the lock expires (24 h by default). And `maxTotalFailedAttempts` (default 20) wrong codes from anyone, with or without tickets, disable codes for that address for a year. The emailed link always works, so verification emails must include it (`verificationToken`) — and from an address's fourth email in a code lifetime they carry only the link.

## What this package deliberately does not do

- No RBAC decisioning — no scope catalogue, no wildcard permission matcher, no `requirePermission()`/`<Can>` component. Bring your own.
- No message bus, SMTP, or push integration — use the hooks.
- No secrets-vault client (Infisical, AWS Secrets Manager, ...) — resolve your own config values before calling `initIdentityProvider()`.
- No QR-code rendering — `setupMfaHandler` returns the raw `otpauth://` URI; render your own QR code client-side.

## License

MIT © Okeav
