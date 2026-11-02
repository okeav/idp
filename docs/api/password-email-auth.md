---
title: "Password & Email Auth"
package: "@okeav/idp-core"
category: "api-reference"
tags: ["auth", "password", "sessions"]
description: "Registration, login, refresh/logout, password reset/change, self-service profile, and session management handlers."
---

# Password & Email Auth

The primary username/password auth flow, plus self-service account and session management.
Sixteen handlers, all exported from `src/password-auth/controllers.js`.

## Shared session mechanics

Every login method in this package (password, MFA-verify, magic link, WebAuthn, SSO) funnels
through the same internal helpers in `src/password-auth/controllers.js` (module exports used by the
other flows — not part of the public package surface):

- **`issueSession(state, { user, claims, req })`** — mints an access token (`issueAccessToken`,
  carrying `auth_time` = now) and an opaque refresh token, then persists both via
  `sessionRepository.createSessionForLogin(...)` — a single atomic Mongo transaction writing the
  session, an access-token audit record, and `lastLoginAt` together (see
  [Repository Adapters](repository-adapters.md)). The session row is `kind: 'first_party'`,
  records `authTime`, and starts a new **refresh-token family** (`familyId`, `familyCreatedAt` —
  see [Refresh & logout](#refresh--logout)). The session's `jti` is set equal to the paired
  access token's `jti`, so `authContextMiddleware` can resolve a presented access token to its
  session row (`findByJti`, under `session.verifyOnEachRequest`) or to a revocation-cache entry
  keyed by that `jti`. New-device detection runs **before** the session row is written (otherwise
  the device would always already be "known"); if the device is new, `onNewDeviceLogin` fires
  (fire-and-forget, `.catch`-guarded). A user's first-ever login never counts as a new device.
- **`setSessionCookies(res, state, session)`** — sets `access_token`/`refresh_token` cookies via
  `cookieOptions()`: `{ httpOnly: true, secure: config.cookies.secure ?? (NODE_ENV !== 'development'), sameSite: config.cookies.sameSite || 'lax', path: '/', domain?: config.cookies.domain }`.
  `secure` defaults to **true** in every environment except `NODE_ENV === 'development'` with no
  explicit override.
- **`refreshTokenInBody`** — the refresh token is also returned in login/refresh JSON bodies (for
  non-browser clients) unless **`config.cookies.refreshTokenInBody: false`** (env
  `IDP_COOKIE_REFRESH_TOKEN_IN_BODY=false`). Set that for browser-only apps: the token then lives
  only in its httpOnly cookie, out of reach of page script.
- **`resolveClaims(state, user, ctx)`** — calls `hooks.resolveAuthContext(user, ctx)`, returns
  `result?.claims ?? {}`.
- **`assertUsableStatus(user)`** — throws based on `user.status`: `LOCKED` → `ACCOUNT_LOCKED` 423;
  `SUSPENDED`/`DISABLED` → `ACCOUNT_SUSPENDED` 403; `PENDING_VERIFICATION`/`INVITED` →
  `PENDING_VERIFICATION` 403; `DELETED` → `INVALID_CREDENTIALS` 401 (**deliberately
  indistinguishable from a wrong password** — a soft-deleted account's login attempts look
  identical to bad credentials); any other value → `USER_NOT_ACTIVE` 403; `ACTIVE` returns
  silently. (Password login never reaches the `LOCKED` branch — see [Login](#login).)

## Hooks on enumeration-sensitive endpoints

Register, resend-verification and forgot-password (and magic-link request) must answer the same
whether or not an account exists. Their email hooks — `onVerificationEmailRequested`,
`onPasswordResetRequested` — and their audit events are therefore **started but not awaited**: if
the response waited for an email to be sent, it would come back measurably later for real
accounts. The hook's first synchronous step still runs before the response. In a serverless
runtime, make those hooks hand off quickly (enqueue rather than send inline). Every other hook is
awaited for at most `config.hookTimeoutMs` (default 10 s); a hook that runs longer keeps running,
but the request carries on.

## Registration

**`POST /register`** — body `{ email, password, firstName?, lastName?, metadata? }`
(`registerSchema`, `.strict()`).

Password policy (enforced by zod, applies everywhere a *new* password is set — register, reset,
change — not on login): min 8 / max 128 chars **and at most 72 bytes of UTF-8** (bcrypt ignores
everything past 72 bytes, so longer passwords are refused rather than silently truncated — that's
72 ASCII characters, fewer with multi-byte characters), must contain uppercase, lowercase, a
number, and a special character (`PASSWORD_POLICY_DEFAULTS`).

`metadata` is **ignored** unless `config.registration.acceptMetadata: true`; then it's persisted
verbatim on the user record (never interpreted) and handed to `resolveAuthContext`. It's written
by whoever registers, so never keep a role, tenant or plan there — see
[Storing App-Specific User Data](../examples/consumer-managed-app-data.md).

Rate limited per IP (`register:ip:<ip>` against `config.rateLimiting.register`, 10/hour default)
and per address (`verification-email:<email hash>` against
`config.rateLimiting.verificationEmailByEmail`, 3/hour default) — both fail-closed (a limiter
backend error → 503 `RATE_LIMITER_UNAVAILABLE`), and both counted on every request, before the
address is looked up.

**Always responds `201 { status: 'ok' }`** — identical whether the email was new, pending, or
already active (enumeration-safe). The password is bcrypt-hashed on every path, so response timing
doesn't leak whether an account exists either.

- **New address**: creates the user in `PENDING_VERIFICATION` status, mints **both** a 32-byte
  opaque verification token *and* a separate 6-digit numeric code (`crypto.randomInt(100000,
  1000000)`) — stored together (both as HMACs) so your email template can offer either a link or
  a code — and fires `auditLog('REGISTERED', ...)` + `onVerificationEmailRequested({ email,
  firstName, lastName, verificationToken, verificationCode })`.
- **Address still `PENDING_VERIFICATION`**: nobody has proven they own it yet, so the newest
  registration **replaces** the stored password and name, every earlier code/link is deleted, and
  a fresh token+code pair is sent (`auditLog('REGISTRATION_RESTARTED')` +
  `onVerificationEmailRequested`). This stops an attacker pre-registering a victim's email with a
  password they know and having the victim activate it.
- **Any other existing account**: untouched; no email is sent.

**`POST /register/verify-email`** — body `{ email, token? | code? }` (`.refine`s that at least one
of `token`/`code` is present). If `token` is provided it's preferred over `code`. Rate limited per
IP (`email-verification:ip:<ip>` against `config.rateLimiting.emailVerification`, 20/15min
default, fail-closed).

- **Enumeration-safe**: an unknown address, an already-verified one, and a wrong code all answer
  the same 400 `INVALID_OR_EXPIRED_TOKEN`. (So a second click on an already-used verification link
  gets 400, not `ok`.)
- **Per-account attempt limit** (`config.security.verificationCodeLockout`, default 5 wrong
  tokens/codes per 3600 s window, locked for 900 s). Attempts are counted **before** the code is
  checked, so a concurrent burst gets no more guesses than the budget. The wrong attempt that uses
  up the budget deletes **every** outstanding verification code for the account (fires
  `auditLog('EMAIL_VERIFICATION_LOCKED')`) and answers 429 `VERIFICATION_LOCKED`; so does every
  further attempt while locked. The owner requests a new code (which goes to their inbox). The
  counter lives in the `attemptCounterRepository` when your storage adapter has one (shared by
  every instance), otherwise in-process.
- On success: promotes to `ACTIVE`, resets `failedLoginAttempts`/`lockUntil`, deletes **all**
  outstanding `email_verification` tokens for the user, fires `auditLog('EMAIL_VERIFIED')`, and
  answers `200 { status: 'ok', userId, email }`.

Codes issued before 0.4.0 were stored in plain text; they keep working until they expire.

Errors: `INVALID_OR_EXPIRED_TOKEN` (400), `VERIFICATION_LOCKED` (429), `RATE_LIMIT_EXCEEDED` (429).

**`POST /register/resend-verification`** — body `{ email }`. Always `200 { status: 'ok' }` —
unknown, already-verified and pending addresses get the same answer. Rate limited by the same
`register` (per IP) and `verificationEmailByEmail` (per address) limits as `/register`. For a
pending account it deletes prior tokens before minting a new token+code pair (old links/codes
become invalid) and fires `onVerificationEmailRequested`.

## Login

**`POST /login`** — body `{ email, password }` (password here is just `z.string().min(1).max(1024)`
— the strong-password policy is **not** re-applied on login, correctly, since it must accept legacy
passwords). Rate limited on two independent keys: `login:ip:<ip>` against
`config.rateLimiting.login` (10/15min default) and `login:email:<email hash>` against
`config.rateLimiting.loginByEmail` (5/15min default). Both fail closed: a rate-limiter backend
error → 503 `RATE_LIMITER_UNAVAILABLE`. (Per-address keys use the email's keyed hash, so the
limiter backend and logs never hold the address; IPv6 clients are keyed by their /64.)

**Auto-unlock on attempt**: if the account is `LOCKED` and `lockUntil` has already passed, the
handler resets it to `ACTIVE` (clearing `failedLoginAttempts`/`lockUntil`) *before* checking the
password on this same request — there's no separate background unlock job.

**Timing-safe non-enumeration**: a nonexistent email still runs `compareDummyPassword` so the
response takes comparable time to a wrong-password attempt against a real account. An account with
no password (SSO- or magic-link-only) does the same dummy work and fails like a wrong password —
it doesn't 500.

**While locked, every password gets 401 `INVALID_CREDENTIALS`** — the right one included. If the
lock answered differently for the right password, it would become a password oracle. The lock was
announced through `onSuspiciousActivityDetected`; a password reset lifts it.

**Failed-attempt lockout**: only counted while `user.status === ACTIVE` (a bad password against a
`PENDING_VERIFICATION` account isn't counted at all). Locks when
`failedAttempts >= config.security.maxFailedLoginAttempts` (default 5), setting `lockUntil = now +
config.security.accountLockDurationMs` (default 30min) and firing `auditLog('ACCOUNT_LOCKED', ...)`
+ `onSuspiciousActivityDetected`. Wrong MFA codes don't count here — MFA has its own lockout (see
[MFA](mfa.md)).

**MFA branch**: if `user.mfaEnabled`, responds `200 { mfaRequired: true, mfaChallengeToken,
expiresIn: config.ttls.mfaChallenge }` (note: `expiresIn` is a **duration in seconds**, unlike
every other endpoint here which returns absolute `...ExpiresAt` timestamps) — no session issued
yet; complete via [`verifyMfaChallengeHandler`](mfa.md) or the WebAuthn-MFA flow. The challenge
token completes one login only.

**Success (no MFA)**: sets cookies + `200 { accessToken, accessTokenExpiresAt, refreshToken,
refreshTokenExpiresAt, userId }` (`refreshToken` omitted when `cookies.refreshTokenInBody: false`).

**Errors**: `INVALID_CREDENTIALS` (401 — unknown user, wrong password, locked account, or `DELETED`
status) plus whatever `assertUsableStatus` throws for suspended/pending accounts.

## Refresh & logout

> **Revocation and access tokens.** With `config.session.verifyOnEachRequest` on (the default
> since 0.3.0), every revocation below — refresh rotation, reuse detection, logout, logout-all,
> password reset/change, `DELETE /me`, `DELETE /me/sessions[/:id]` — kills the affected access
> tokens on every instance at once, because `authContextMiddleware` checks the session row on each
> request. The revocation-cache notes below (which operations write a `jti` entry, and that bulk
> ones don't) only decide behaviour when it's set to `false` — then tokens from bulk-revoked
> sessions stay valid until natural expiry. See [Middleware](middleware.md).

**Session kinds.** Session rows are `kind: 'first_party'` (a login on this IdP) or `kind:
'oauth2'` (an OAuth2 client's grant). `/refresh` accepts only `first_party` rows; an OAuth2 client's
refresh token presented here is refused with `INVALID_REFRESH_TOKEN` and **stays revoked** (it
leaked). Rows written before 0.4.0 have no `kind` and are classified by their stored claims
(`{ clientId, scopes[] }` = OAuth2).

**Refresh-token families.** A login starts a family (`familyId`, `familyCreatedAt`); every
rotation adds a row to it. Two rules hang off that:

- **Absolute lifetime** — a family ends `config.session.absoluteLifetimeSeconds` (default 90 days)
  after its login, however actively it's refreshed: no refresh token's expiry is set past that, and
  a refresh after it answers `INVALID_REFRESH_TOKEN` ("maximum lifetime"). The usual sliding
  `ttls.refreshToken` (30 days) applies inside it.
- **Reuse detection** — presenting a refresh token that was already *rotated* means someone holds
  a copy, so the whole family is revoked (both the thief and the legitimate client must log in
  again) and `auditLog('REFRESH_TOKEN_REUSE_DETECTED')` fires. Within
  `config.session.refreshReuseGraceSeconds` (default 10 s — two tabs refreshing at once) a replay
  is only refused. Needs the storage methods `findByRefreshTokenHash` and `revokeFamily`; an
  adapter without `revokeFamily` just refuses the replay.

**`POST /refresh`** — reads the refresh token from the `refresh_token` **cookie** or
`req.body.refreshToken` (cookie wins). The body is validated by `refreshSchema` (`{ refreshToken? }`,
a string of at most 512 characters). Rate limited: `refresh:ip:<ip>` against
`config.rateLimiting.refreshToken` (30/min default — fail-open, it's load-shedding). When the token
came from the cookie, the request is subject to the [CSRF origin check](middleware.md#csrf-origin-check)
(`cookies.trustedOrigins`).

**Rotates on every use**: revokes the presented refresh token
(`sessionRepository.revokeByRefreshTokenHash(hash, { reason: 'rotated' })`) and issues a brand-new
access+refresh pair in the same family (a plain `createSession`, not the transactional
`createSessionForLogin` — this isn't a new login). The new access token keeps the **original
login's `auth_time`** — a refresh never counts as a recent login for
[`requireRecentAuth`](middleware.md#requirerecentauthopts). Also writes a revocation-cache entry for
the **old** access token's `jti` (`config.ttls.revocationCache`, default 3600s) so it stops working
immediately rather than at natural JWT expiry (it's also refused through its now-revoked session
row).

**Claims are re-resolved on every refresh** by default (`config.session.reresolveClaimsOnRefresh`,
default **`true`** since 0.4.0): `resolveAuthContext` runs again with `{ isNewUser: false, method:
'refresh' }`, so a role change or suspension in your app takes effect at the next access-token
rotation instead of the next full login. Keep the hook fast. Set it to `false` to carry the
login-time claims forward unchanged — they then stay frozen for the whole family (up to
`absoluteLifetimeSeconds`).

**Racing "log out everywhere".** Logout-all, password reset/change and account deletion record
`sessionsRevokedAt` on the user *before* revoking the rows; a refresh re-checks it after writing
its successor and, if the chain was revoked meanwhile, revokes the new row and answers 401
`TOKEN_REVOKED`.

Errors: `REFRESH_TOKEN_REQUIRED` (400), `VALIDATION_ERROR` (400, e.g. a non-string token),
`INVALID_REFRESH_TOKEN` (401 — no matching active session, a reused/rotated token, an OAuth2 row,
or the family's absolute lifetime passed), `TOKEN_REVOKED` (401), `USER_NOT_ACTIVE` (403),
`CSRF_ORIGIN_REJECTED` (403).

**`POST /logout`** — body `{ refreshToken? }` (`logoutSchema`; the body itself may be omitted).
Reads the refresh token from `req.body.refreshToken` or, when the body omits it, the httpOnly
`refresh_token` cookie (body wins — opposite precedence from `/refresh`); a cookie-based logout is
subject to the [CSRF origin check](middleware.md#csrf-origin-check). Revokes the session
(`onlyIfActive: false` — explicitly allows revoking an already-inactive row) and, if found, writes
a revocation-cache entry for its `jti`. Clears both cookies with the same attributes they were set
with (including `config.cookies.domain`). Errors: `REFRESH_TOKEN_REQUIRED` (400) if no token found
anywhere.

**`POST /logout/all`** (auth required) — records `sessionsRevokedAt`, then revokes every session
for the caller (`revokeAllForUser`) but, unlike `revokeAllSessionsHandler` below, does **not**
return `revokedCount` and does **not** write per-session revocation-cache entries — with
`session.verifyOnEachRequest: false`, already-issued access tokens for those sessions stay valid
until natural expiry. Fires `auditLog('LOGOUT_ALL', ...)`.

## Password management

**`POST /password/forgot`** — body `{ email }`. Always `200 { status: 'ok' }` (enumeration-safe —
silent no-op if the email is unknown or the account is deleted, no audit log fired in that case
either). Rate limited per IP (`password-reset:ip:<ip>` against `config.rateLimiting.passwordReset`,
3/hour default) **and** per address (`password-reset:email:<email hash>` against
`config.rateLimiting.passwordResetByEmail`, 3/hour default), both fail-closed (503
`RATE_LIMITER_UNAVAILABLE` on a backend error). Only the newest link works: a new request deletes
the account's earlier reset tokens. Reset token: 32-byte opaque, hash-only (no numeric-code
counterpart, unlike email verification). Fires `onPasswordResetRequested({ email, resetToken,
firstName?, lastName? })` (detached — see above) only if the user exists.

**`POST /password/reset`** — body `{ email, token, newPassword }` (full password policy).
`INVALID_OR_EXPIRED_TOKEN` (400) for both "no such user" and "token invalid/expired/wrong owner" —
deliberately non-distinguishing. On success: rehashes, sets `passwordChangedAt` (which also voids
any outstanding MFA challenge token), **lifts a lockout** (`LOCKED` → `ACTIVE`, counters cleared),
**revokes all sessions** for the user (forces re-login everywhere), and deletes every other
outstanding reset token. It does **not** fire `onPasswordChanged` (that hook is exclusive to
`/password/change` below) and does not write revocation-cache entries for already-issued access
tokens — they die with their session rows under `session.verifyOnEachRequest` (default), and
otherwise remain valid until natural expiry.

**`POST /password/change`** (auth required) — body `{ currentPassword, newPassword }`.
`CURRENT_PASSWORD_INCORRECT` (400) if the bcrypt compare fails (always the case for an account with
no password). Same rehash + `passwordChangedAt` + revoke-all-sessions pattern as reset, **plus**
fires `onPasswordChanged({ userId, email, firstName, lastName, locale, when, deviceInfo, ipAddress })`.

## Self-service identity ("me")

All require `authContextMiddleware()` (first-party tokens only) → `UNAUTHENTICATED` (401) if
missing.

- **`GET /me`** → `{ userId, email, emailVerified, isActive, status, mfaEnabled, profile,
  createdAt, updatedAt }`. `emailVerified` is **derived**, not a stored field:
  `status !== 'PENDING_VERIFICATION'` — so `LOCKED`/`SUSPENDED`/`DISABLED`/`DELETED` all read
  `emailVerified: true` too; only the pending-verification state reads `false`. `isActive` is
  strictly `status === 'ACTIVE'`.
- **`PATCH /me`** — body may include any of `firstName, lastName, displayName, avatarUrl, locale,
  zoneinfo` (`updateProfileSchema`, all optional). `avatarUrl` must be an `https` URL (it's
  released as the ID token's `picture`); `locale` must be a BCP 47 tag and `zoneinfo` an IANA
  zone name. Builds a sparse dotted-path patch — only keys explicitly present (`!== undefined`)
  are updated; omitted keys are left untouched, not nulled. → `{ userId, profile, updatedAt }`.
- **`DELETE /me`** — also requires a **recent login**
  ([`requireRecentAuth()`](middleware.md#requirerecentauthopts), default within 15 minutes; else 401
  `REAUTHENTICATION_REQUIRED`). **Soft delete**: sets `status: 'DELETED'` (record is not removed)
  and revokes all sessions. Combined with `assertUsableStatus`'s `DELETED → INVALID_CREDENTIALS`
  mapping, a deleted user's future login attempts are indistinguishable from wrong credentials.
- **`GET /me/sessions`** → array of `{ id, ipAddress, deviceInfo, createdAt, expiresAt }` — does
  **not** expose `deviceFingerprint`, `jti`, `kid`, `claims`, or `tokenHash` even though those
  fields exist on the stored record.
- **`DELETE /me/sessions/:id`** → `REFRESH_TOKEN_NOT_FOUND` (404) if the session doesn't exist,
  isn't owned by the caller, or the id is malformed (all collapse to the same error). On success,
  proactively revokes the session's `jti` in the cache (kills its access token immediately) —
  **unlike** the bulk variant below.
- **`DELETE /me/sessions`** → revokes every session and returns `{ status: 'ok', revokedCount }`.
  Does **not** write per-session revocation-cache entries (same caveat as `/logout/all`) —
  functionally overlaps with `/logout/all` but reports `revokedCount` and fires a different audit
  event (`SESSIONS_REVOKED_ALL` vs `LOGOUT_ALL`).

## Related

- [MFA](mfa.md) — completes the `mfaRequired` challenge this flow issues.
- [Magic Link](magic-link.md), [WebAuthn](webauthn.md), [SSO / Social Login](sso-social-login.md) —
  alternative login methods sharing `issueSession`/`resolveClaims`/`assertUsableStatus`.
- [Middleware](middleware.md) — `authContextMiddleware`, `requireRecentAuth`, the CSRF origin check.
- [Rate Limiter Interface](rate-limiter-interface.md), [Cache Interface](cache-interface.md)
- [Register, Login, Refresh example](../examples/register-login-refresh-logout.md)
