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
through the same internal helpers, also individually exported for reuse:

- **`issueSession(state, { user, claims, req })`** — mints an access token (`issueAccessToken`)
  and an opaque refresh token, then persists both via
  `sessionRepository.createSessionForLogin(...)` — a single atomic Mongo transaction writing the
  session, an access-token audit record, and `lastLoginAt` together (see
  [Repository Adapters](repository-adapters.md)). The session's `jti` is set equal to the paired
  access token's `jti`, so a revocation-cache write keyed by this `jti` is checked by
  `authContextMiddleware` against the presented access token without a second lookup. Also fires
  (fire-and-forget, `.catch`-guarded) new-device detection.
- **`setSessionCookies(res, state, session)`** — sets `access_token`/`refresh_token` cookies via
  `cookieOptions()`: `{ httpOnly: true, secure: config.cookies.secure ?? (NODE_ENV !== 'development'), sameSite: config.cookies.sameSite || 'lax', path: '/', domain?: config.cookies.domain }`.
  `secure` defaults to **true** in every environment except `NODE_ENV === 'development'` with no
  explicit override.
- **`resolveClaims(state, user, ctx)`** — calls `hooks.resolveAuthContext(user, ctx)`, returns
  `result?.claims ?? {}`.
- **`assertUsableStatus(user)`** — throws based on `user.status`: `LOCKED` → `ACCOUNT_LOCKED` 423;
  `SUSPENDED`/`DISABLED` → `ACCOUNT_SUSPENDED` 403; `PENDING_VERIFICATION`/`INVITED` →
  `PENDING_VERIFICATION` 403; `DELETED` → `INVALID_CREDENTIALS` 401 (**deliberately
  indistinguishable from a wrong password** — a soft-deleted account's login attempts look
  identical to bad credentials); any other value → `USER_NOT_ACTIVE` 403; `ACTIVE` returns
  silently.

## Registration

**`POST /register`** — body `{ email, password, firstName?, lastName?, metadata? }`
(`registerSchema`, `.strict()`).

Password policy (enforced by zod, applies everywhere a *new* password is set — not on login):
min 8 / max 128 chars, must contain uppercase, lowercase, a number, and a special character
(`PASSWORD_POLICY_DEFAULTS`). `metadata` is an arbitrary `Record<string, unknown>` persisted
verbatim on the user record, never interpreted.

**Always responds `201 { status: 'ok' }`** — identical whether the email was new or already
existed (enumeration-safe). If the email already exists, the handler still runs
`compareDummyPassword(password)` (a bcrypt compare against a fixed dummy hash) before returning,
so the two code paths take comparable wall-clock time and response timing doesn't leak whether an
account exists.

On the new-user path: creates the user in `PENDING_VERIFICATION` status, mints **both** a 32-byte
opaque verification token *and* a separate 6-digit numeric code (`crypto.randomInt(100000,
1000000)`) — stored together so your email template can offer either a link or a code — and fires
`auditLog('REGISTERED', ...)` + `onVerificationEmailRequested({ email, firstName, lastName,
verificationToken, verificationCode })`.

**`POST /register/verify-email`** — body `{ email, token? | code? }` (`.refine`s that at least one
of `token`/`code` is present). If `token` is provided it's preferred over `code` (both sent →
`code` ignored). Idempotent: already-verified users get `200 { status: 'ok' }` with no
`userId`/`email` fields and no error. On success, promotes to `ACTIVE`, resets
`failedLoginAttempts`/`lockUntil`, and deletes **all** outstanding `email_verification` tokens for
the user (not just the consumed one). Errors: `USER_NOT_FOUND` (404),
`INVALID_OR_EXPIRED_TOKEN` (400).

**`POST /register/resend-verification`** — body `{ email }`. Silent no-op (`200 { status: 'ok' }`)
if the email doesn't exist (enumeration-safe). `EMAIL_ALREADY_VERIFIED` (400) if the user isn't
`PENDING_VERIFICATION`. Deletes prior tokens before minting a new token+code pair (old links/codes
become invalid).

## Login

**`POST /login`** — body `{ email, password }` (password here is just `z.string().min(1)` — the
strong-password policy is **not** re-applied on login, correctly, since it must accept legacy
passwords). Rate limited on two independent keys: `login:ip:<req.ip>` against
`config.rateLimiting.login` (10/15min default) and `login:email:<normalized email>` against
`config.rateLimiting.loginByEmail` (5/15min default).

**Auto-unlock on attempt**: if the account is `LOCKED` and `lockUntil` has already passed, the
handler resets it to `ACTIVE` (clearing `failedLoginAttempts`/`lockUntil`) *before* checking the
password on this same request — there's no separate background unlock job.

**Timing-safe non-enumeration**: a nonexistent email still runs `compareDummyPassword` so the
response takes comparable time to a wrong-password attempt against a real account.

**Failed-attempt lockout**: only counted while `user.status === ACTIVE` (a bad password against a
`PENDING_VERIFICATION` account isn't counted at all). Locks when
`failedAttempts >= config.security.maxFailedLoginAttempts` (default 5), setting `lockUntil = now +
config.security.accountLockDurationMs` (default 30min) and firing `auditLog('ACCOUNT_LOCKED', ...)`
+ `onSuspiciousActivityDetected`.

**MFA branch**: if `user.mfaEnabled`, responds `200 { mfaRequired: true, mfaChallengeToken,
expiresIn: config.ttls.mfaChallenge }` (note: `expiresIn` is a **duration in seconds**, unlike
every other endpoint here which returns absolute `...ExpiresAt` timestamps) — no session issued
yet; complete via [`verifyMfaChallengeHandler`](mfa.md) or the WebAuthn-MFA flow.

**Success (no MFA)**: sets cookies + `200 { accessToken, accessTokenExpiresAt, refreshToken,
refreshTokenExpiresAt, userId }`.

**Errors**: `INVALID_CREDENTIALS` (401, unknown user, wrong password, or `DELETED` status) plus
whatever `assertUsableStatus` throws for locked/suspended/pending accounts.

## Refresh & logout

**`POST /refresh`** — reads the refresh token from the `refresh_token` **cookie** or
`req.body.refreshToken` (cookie wins). No dedicated zod schema — body shape isn't validated by a
mounted schema in `buildRouter()`. Rate limited: `refresh:ip:<req.ip>` against
`config.rateLimiting.refreshToken` (30/min default).

**Rotates on every use**: revokes the presented refresh token
(`sessionRepository.revokeByRefreshTokenHash`) and issues a brand-new access+refresh pair
(a plain `createSession`, not the transactional `createSessionForLogin` — this isn't a new login).
Also writes a revocation-cache entry for the **old** access token's `jti`
(`config.ttls.revocationCache`, default 3600s) so it stops working immediately rather than at
natural JWT expiry. By default, claims are **carried forward unchanged** from the prior session —
refresh does **not** call `resolveAuthContext` again. Set **`config.session.reresolveClaimsOnRefresh:
true`** (default `false`) to re-derive claims from `resolveAuthContext` on every refresh instead —
useful if claims (roles/permissions/tenant) can change between refreshes and should be picked up
without forcing a full re-login.

Errors: `REFRESH_TOKEN_REQUIRED` (400), `INVALID_REFRESH_TOKEN` (401, no matching active session),
`USER_NOT_ACTIVE` (403).

**`POST /logout`** — reads the refresh token from `req.body.refreshToken` or the cookie (body wins
— opposite precedence from `/refresh`). Revokes the session (`onlyIfActive: false` — explicitly
allows revoking an already-inactive row) and, if found, writes a revocation-cache entry for its
`jti`. Clears both cookies via `res.clearCookie(name)` with **no options argument** — if you've
configured a non-default `config.cookies.domain`, the browser may not actually clear the cookie
without a matching `domain`/`path`; consider clearing explicitly on your own error-handling layer
if you hit this. Errors: `REFRESH_TOKEN_REQUIRED` (400) if no token found anywhere.

**`POST /logout/all`** (auth required) — revokes every session for the caller
(`revokeAllForUser`) but, unlike `revokeAllSessionsHandler` below, does **not** return
`revokedCount` and does **not** write per-session revocation-cache entries — already-issued access
tokens for those sessions stay valid until natural expiry. Fires `auditLog('LOGOUT_ALL', ...)`.

## Password management

**`POST /password/forgot`** — body `{ email }`. Always `200 { status: 'ok' }` (enumeration-safe —
silent no-op if the email is unknown, no audit log fired in that case either). Rate limited:
`password-reset:ip:<req.ip>` against `config.rateLimiting.passwordReset` (3/hour default). Reset
token: 32-byte opaque, hash-only (no numeric-code counterpart, unlike email verification). Fires
`onPasswordResetRequested({ email, resetToken, firstName?, lastName? })` only if the user exists.

**`POST /password/reset`** — body `{ email, token, newPassword }` (full password policy).
`INVALID_OR_EXPIRED_TOKEN` (400) for both "no such user" and "token invalid/expired/wrong owner" —
deliberately non-distinguishing. On success: rehashes, sets `passwordChangedAt`, and **revokes all
sessions** for the user (forces re-login everywhere) — but does **not** fire `onPasswordChanged`
(that hook is exclusive to `/password/change` below) and does not proactively revoke
already-issued access tokens' `jti`s (they remain valid until natural expiry despite the session
revocation).

**`POST /password/change`** (auth required) — body `{ currentPassword, newPassword }`.
`CURRENT_PASSWORD_INCORRECT` (400) if the bcrypt compare fails. Same rehash +
`passwordChangedAt` + `revokeAllForUser` pattern as reset, **plus** fires
`onPasswordChanged({ userId, email, firstName, lastName, locale, when, deviceInfo, ipAddress })`.

## Self-service identity ("me")

All require `authContextMiddleware()` → `UNAUTHENTICATED` (401) if missing.

- **`GET /me`** → `{ userId, email, emailVerified, isActive, status, mfaEnabled, profile,
  createdAt, updatedAt }`. `emailVerified` is **derived**, not a stored field:
  `status !== 'PENDING_VERIFICATION'` — so `LOCKED`/`SUSPENDED`/`DISABLED`/`DELETED` all read
  `emailVerified: true` too; only the pending-verification state reads `false`. `isActive` is
  strictly `status === 'ACTIVE'`.
- **`PATCH /me`** — body may include any of `firstName, lastName, displayName, avatarUrl, locale,
  zoneinfo` (`updateProfileSchema`, all optional). Builds a sparse dotted-path patch — only keys
  explicitly present (`!== undefined`) are updated; omitted keys are left untouched, not nulled.
  → `{ userId, profile, updatedAt }`.
- **`DELETE /me`** — **soft delete**: sets `status: 'DELETED'` (record is not removed) and revokes
  all sessions. Combined with `assertUsableStatus`'s `DELETED → INVALID_CREDENTIALS` mapping, a
  deleted user's future login attempts are indistinguishable from wrong credentials.
- **`GET /me/sessions`** → array of `{ id, ipAddress, deviceInfo, createdAt, expiresAt }` — does
  **not** expose `deviceFingerprint`, `jti`, `kid`, `claims`, or `tokenHash` even though those
  fields exist on the stored record.
- **`DELETE /me/sessions/:id`** → `REFRESH_TOKEN_NOT_FOUND` (404) if the session doesn't exist *or*
  isn't owned by the caller (both cases collapse to the same error). On success, proactively
  revokes the session's `jti` in the cache (kills its access token immediately) —
  **unlike** the bulk variant below.
- **`DELETE /me/sessions`** → revokes every session and returns `{ status: 'ok', revokedCount }`.
  Does **not** write per-session revocation-cache entries (same caveat as `/logout/all`) —
  functionally overlaps with `/logout/all` but reports `revokedCount` and fires a different audit
  event (`SESSIONS_REVOKED_ALL` vs `LOGOUT_ALL`).

## Related

- [MFA](mfa.md) — completes the `mfaRequired` challenge this flow issues.
- [Magic Link](magic-link.md), [WebAuthn](webauthn.md), [SSO / Social Login](sso-social-login.md) —
  alternative login methods sharing `issueSession`/`resolveClaims`/`assertUsableStatus`.
- [Rate Limiter Interface](rate-limiter-interface.md), [Cache Interface](cache-interface.md)
- [Register, Login, Refresh example](../examples/register-login-refresh-logout.md)
