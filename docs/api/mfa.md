---
title: "Multi-Factor Authentication (TOTP)"
package: "@okeav/idp-core"
category: "api-reference"
tags: ["auth", "mfa", "totp"]
description: "MFA setup, confirmation, disable, recovery codes, and challenge verification via otplib TOTP."
---

# Multi-Factor Authentication (TOTP)

Time-based one-time password (TOTP) second factor, via `otplib`. All six handlers exported from
`src/mfa/controller.js`. TOTP verification uses `{ strategy: 'totp', epochTolerance: 30 }` — a
30-second clock-skew tolerance either side of the current step.

> Every handler here except `verifyMfaChallengeHandler` reads `req.auth.userId` directly with no
> explicit `UNAUTHENTICATED` guard — they rely on `authContextMiddleware()` being mounted in front
> of them (as `buildRouter()` does). If you wire these handlers individually, mount
> `authContextMiddleware()` first or a raw `TypeError` will propagate instead of a structured
> `IdpError`.

## `GET /me/mfa` — `getMfaStatusHandler`

No body. → `{ mfaEnabled: boolean }`. `USER_NOT_FOUND` (404).

## `POST /me/mfa/setup` — `setupMfaHandler`

No body. Generates a new TOTP secret and stores it in `mfaTempSecret` **only** — `mfaEnabled`
stays `false` and the confirmed `mfaSecret` is untouched until `confirmMfaHandler` succeeds.
Calling setup again before confirming simply overwrites `mfaTempSecret` (no error on repeat calls
while `mfaEnabled` is still false).

→ `{ secret, otpauthUrl }` — `otpauthUrl` is a raw `otplib`-generated `otpauth://` URI
(`label: user.email, issuer: config.mfa.issuerLabel, strategy: 'totp'`). **This package does not
render a QR code** — render one client-side from `otpauthUrl`.

Errors: `USER_NOT_FOUND` (404); `MFA_ALREADY_ENABLED` (400).

## `POST /me/mfa/confirm` — `confirmMfaHandler`

Body: `{ code: string (6-10 chars) }`. Verifies `code` against `mfaTempSecret`. On success:
promotes `mfaTempSecret → mfaSecret`, nulls `mfaTempSecret`, sets `mfaEnabled: true`, and
**generates recovery codes at this point** (not at setup time) — count from
`config.mfa.recoveryCodeCount` (default 10). Each code: two 3-byte hex groups joined by a hyphen
(`XXXXXX-XXXXXX`). Stored server-side only as `{ codeHash: HMAC-SHA256(code), usedAt: null }` —
raw codes are never persisted.

→ `{ mfaEnabled: true, recoveryCodes: [...] }` — **shown once, in plaintext.** Your UI must prompt
the user to save these; there's no way to retrieve them again short of regenerating (which
invalidates the old set).

Errors: `USER_NOT_FOUND` (404); `MFA_ALREADY_ENABLED` (400); `MFA_SETUP_REQUIRED` (400, no
`mfaTempSecret` present — call setup first); `INVALID_MFA_CODE` (400).

## `DELETE /me/mfa` — `disableMfaHandler`

Body: `{ password: string, code: string (6-10 chars) }`. Password checked **before** the TOTP
code. Fully resets MFA state: `mfaEnabled: false, mfaSecret: null, mfaTempSecret: null,
mfaRecoveryCodes: []` — all recovery codes are discarded too, not just the submitted TOTP.

→ `{ mfaEnabled: false }`.

Errors: `USER_NOT_FOUND` (404); `MFA_NOT_ENABLED` (400); `CURRENT_PASSWORD_INCORRECT` (400);
`INVALID_MFA_CODE` (400).

## `POST /me/mfa/recovery-codes` — `regenerateRecoveryCodesHandler`

Body: `{ password: string }` — **no TOTP code required**, password alone. Fully replaces
`mfaRecoveryCodes` (old codes, used or unused, are invalidated wholesale).

→ `{ recoveryCodes: [...] }` (plaintext, shown once, same generation scheme as confirm).

Errors: `USER_NOT_FOUND` (404); `MFA_NOT_ENABLED` (400); `CURRENT_PASSWORD_INCORRECT` (400).

## `POST /mfa/verify` — `verifyMfaChallengeHandler`

**No auth required** — identity comes from the challenge token, not `req.auth`. Completes the
`mfaRequired` response `loginHandler` returns when `user.mfaEnabled`. Body:
`{ mfaChallengeToken: string, code: string (6-10 chars) }`. Rate limited:
`mfa-challenge:ip:<req.ip>` against `config.rateLimiting.mfaChallenge` (5/15min default).

**Verification order**: TOTP against `mfaSecret` first; **only if that fails**, falls back to
scanning `mfaRecoveryCodes` for an unused entry (`usedAt` falsy) whose hash
(`crypto.timingSafeEqual`, length-checked first) matches the submitted code. A matched recovery
code is marked `usedAt: <now>` but **not removed** from the array (kept for audit history).

On **total failure** (neither TOTP nor any recovery code matched), the handler calls
`incrementFailedLoginAttempts` directly — but, **unlike password login's lockout path, it never
checks the result against `maxFailedLoginAttempts` or applies an account lock.** Repeated bad MFA
codes accumulate `failedLoginAttempts` silently without ever triggering `ACCOUNT_LOCKED` or
`onSuspiciousActivityDetected` through this endpoint — brute-forcing the MFA code is only
throttled by the IP-based `mfaChallenge` rate limit, not account lockout. Worth factoring into your
own risk model if you rely on the lockout mechanism as a backstop.

**Success**: sets session cookies + `200 { accessToken, accessTokenExpiresAt, refreshToken,
refreshTokenExpiresAt, userId }` — same shape as password login's non-MFA success.

Errors:
- `INVALID_MFA_CHALLENGE_TOKEN` (401) — thrown for two different conditions that surface
  identically: the JWT itself is invalid/expired, **or** it verifies fine but `mfaEnabled` has
  since been turned off (e.g. disabled between challenge issuance and this call).
- `USER_NOT_ACTIVE` (403) — user not found, or not `ACTIVE`.
- `INVALID_MFA_CODE` (400) — neither TOTP nor recovery code matched.

Hooks: `auditLog('MFA_VERIFIED', { userId })`; `resolveAuthContext(user, { isNewUser: false,
method: 'mfa' })`; `onNewDeviceLogin` via `issueSession` if applicable.

## Related

- [Password & Email Auth](password-email-auth.md) — issues the `mfaChallengeToken` this flow
  consumes; shares `issueSession`/cookie mechanics.
- [WebAuthn](webauthn.md) — passkey-as-MFA is an alternative second factor to this TOTP flow,
  consuming the same `mfaChallengeToken`.
- [Tokens & Signing (RS256)](tokens-rs256.md) — `issueMfaChallengeToken`/`verifyMfaChallengeToken`.
- [MFA TOTP Setup & Verify example](../examples/mfa-totp-setup-and-verify.md)
