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
30-second clock-skew tolerance either side of the current step. A submitted code that isn't
exactly 6 digits is simply not a TOTP match (it never reaches `otplib`, which would throw on it).

**Every TOTP code is single-use.** Each account records the last accepted TOTP time step
(`mfaLastTotpStep`, claimed atomically through `userRepository.claimTotpStep`) and refuses that
step or an earlier one — at login, enrolment, disable and recovery-code regeneration alike. The
code that confirmed enrolment can't then complete a login, and a user who just used a code waits
for the next one before using TOTP again. A replayed step is answered like any wrong code
(`INVALID_MFA_CODE`) and counts toward the lockout.

Secrets are encrypted at rest and failed codes count toward a per-account lockout — see
[Secret encryption at rest](#secret-encryption-at-rest) and
[Per-account lockout](#per-account-lockout) below. With `config.mfa.enabled: false`, setup and
confirm respond 404 `FEATURE_DISABLED`.

> Every handler here except `verifyMfaChallengeHandler` reads `req.auth.userId` directly with no
> explicit `UNAUTHENTICATED` guard — they rely on `authContextMiddleware()` being mounted in front
> of them (as `buildRouter()` does). If you wire these handlers individually, mount
> `authContextMiddleware()` first or a raw `TypeError` will propagate instead of a structured
> `IdpError`. `buildRouter()` also mounts `requireRecentAuth()` in front of `POST /me/mfa/setup`
> and `POST /me/mfa/confirm` — do the same:
>
> ```js
> router.post('/me/mfa/setup', authContextMiddleware(), requireRecentAuth(), setupMfaHandler);
> router.post('/me/mfa/confirm', authContextMiddleware(), requireRecentAuth(),
>     validateBody(schemas.confirmMfaSchema), confirmMfaHandler);
> ```

## `GET /me/mfa` — `getMfaStatusHandler`

No body. → `{ mfaEnabled: boolean }`. `USER_NOT_FOUND` (404).

## `POST /me/mfa/setup` — `setupMfaHandler`

**Requires a recent login** (`requireRecentAuth()`): the access token's `auth_time` must be within
`config.session.recentAuthMaxAgeSeconds` (default 900 s), otherwise 401
`REAUTHENTICATION_REQUIRED` — send the user through a login (password + MFA, magic link, SSO or
passkey; a token refresh doesn't count) and retry with the new token. This stops a stolen session
from enrolling a second factor of its own.

No body. Generates a new TOTP secret and stores it, encrypted, in `mfaTempSecret` **only** — `mfaEnabled`
stays `false` and the confirmed `mfaSecret` is untouched until `confirmMfaHandler` succeeds.
Calling setup again before confirming simply overwrites `mfaTempSecret` (no error on repeat calls
while `mfaEnabled` is still false).

→ `{ secret, otpauthUrl }` (sent with `Cache-Control: no-store`) — `otpauthUrl` is a raw `otplib`-generated `otpauth://` URI
(`label: user.email, issuer: config.mfa.issuerLabel, strategy: 'totp'`). **This package does not
render a QR code** — render one client-side from `otpauthUrl`.

Errors: `REAUTHENTICATION_REQUIRED` (401); `FEATURE_DISABLED` (404, `mfa.enabled: false`);
`USER_NOT_FOUND` (404); `MFA_ALREADY_ENABLED` (400).

## `POST /me/mfa/confirm` — `confirmMfaHandler`

**Requires a recent login** (`requireRecentAuth()`, as for setup).

Body: `{ code: string (6-10 chars) }`. Verifies `code` against `mfaTempSecret`, under the
[per-account lockout](#per-account-lockout) (`method: 'totp-enrolment'`), claiming its time step
(so the same code can't then complete a login). On success: re-encrypts
the temp secret into `mfaSecret` (a legacy plain-text temp secret is sealed here), nulls
`mfaTempSecret`, sets `mfaEnabled: true`, and
**generates recovery codes at this point** (not at setup time) — count from
`config.mfa.recoveryCodeCount` (default 10). Each code: 20 random characters of Crockford base32
(`0-9`, `A-Z` without `I L O U` — 100 bits) shown as four groups of five, `XXXXX-XXXXX-XXXXX-XXXXX`.
(0.3.x codes were 48 bits — with the database and the HMAC key, every user's codes fell to one
offline search.) Stored server-side only as `{ codeHash, usedAt: null }`, where `codeHash` is the
HMAC-SHA256 of `<userId>:<normalized code>` under the recovery-code key derived from
`security.tokenHashSecret` (see [rotating it](bootstrap-config.md#rotating-securitytokenhashsecret)) —
bound to the user, so one guess can't be tested against everyone's codes at once. Raw codes are
never persisted. **Recovery codes issued before 0.4.0 (`XXXXXX-XXXXXX`) no longer verify** (they
were hashed without the user binding) — users who enabled MFA earlier need a new set
(`POST /me/mfa/recovery-codes`).

**Enabling MFA signs out the account's other sessions.** Every other session row is revoked
(`sessionRepository.revokeAllForUser(userId, { exceptJti })`), keeping only the session that
enrolled — any of them could be the reason the user is securing the account. It first bumps the
user's `sessionEpoch` (`userRepository.bumpSessionEpoch(userId, { exceptFamily })`) with the
enrolling session's family exempt, so a refresh of another session that was already in flight is
revoked too; the enrolling family's rows are moved into the new epoch
(`sessionRepository.raiseFamilyEpoch`). The `MFA_ENABLED`
audit event carries `revokedOtherSessions` (the count).

→ `{ mfaEnabled: true, recoveryCodes: [...] }` (`Cache-Control: no-store`) — **shown once, in plaintext.** Your UI must prompt
the user to save these; there's no way to retrieve them again short of regenerating (which
invalidates the old set).

Errors: `REAUTHENTICATION_REQUIRED` (401); `FEATURE_DISABLED` (404); `USER_NOT_FOUND` (404);
`MFA_ALREADY_ENABLED` (400); `MFA_SETUP_REQUIRED` (400, no `mfaTempSecret` present — call setup first); `INVALID_MFA_CODE`
(400); `MFA_LOCKED` (429); the [secret-read errors](#secret-encryption-at-rest) (500).

## `DELETE /me/mfa` — `disableMfaHandler`

Body: `{ password?: string, code: string (6-10 chars) }`. `password` is required when the account
has one; a passwordless account (SSO / magic-link only) re-authenticates with the TOTP code alone.
Runs under the [per-account lockout](#per-account-lockout) (`method: 'totp-disable'`): the attempt
is counted **before** the password is checked, so this route is no password oracle, locked or
not; then the password, then the TOTP code. A wrong password and a wrong code both count as
failures. Fully resets MFA state: `mfaEnabled: false, mfaSecret: null, mfaTempSecret: null,
mfaRecoveryCodes: [], mfaLastTotpStep: null` — all recovery codes are discarded too, not just the
submitted TOTP.

→ `{ mfaEnabled: false }`.

Errors: `USER_NOT_FOUND` (404); `MFA_NOT_ENABLED` (400); `CURRENT_PASSWORD_INCORRECT` (400);
`INVALID_MFA_CODE` (400); `MFA_LOCKED` (429); the [secret-read errors](#secret-encryption-at-rest)
(500).

## `POST /me/mfa/recovery-codes` — `regenerateRecoveryCodesHandler`

Body: `{ password?: string, code: string (6-10 chars) }` — **a current TOTP code is required as
well as the password** (since 0.4.0: whoever holds only a session, or only the password, must not
be able to mint a fresh set of second factors). As for disable, `password` is required only when
the account has one. Runs under the [per-account lockout](#per-account-lockout)
(`method: 'recovery-codes'`); a wrong password or code counts as a failure. Fully replaces
`mfaRecoveryCodes` (old codes, used or unused, are invalidated wholesale).

→ `{ recoveryCodes: [...] }` (plaintext, shown once, same generation scheme as confirm;
`Cache-Control: no-store`).

Errors: `USER_NOT_FOUND` (404); `MFA_NOT_ENABLED` (400); `CURRENT_PASSWORD_INCORRECT` (400);
`INVALID_MFA_CODE` (400); `MFA_LOCKED` (429); the [secret-read errors](#secret-encryption-at-rest)
(500).

## `POST /mfa/verify` — `verifyMfaChallengeHandler`

**No auth required** — identity comes from the challenge token, not `req.auth`. Completes the
`mfaRequired` response `loginHandler` returns when `user.mfaEnabled`. Body:
`{ mfaChallengeToken: string, code: string (6-32 chars) }` — a TOTP code or a recovery code
(`XXXXX-XXXXX-XXXXX-XXXXX`, 23 chars with the dashes). A `login_challenge` given to the first factor rides in the challenge token (claim `lch`) and is bound to the session created here, as with `/webauthn/mfa/verify` — see [Login challenges](oauth2-authorization-server.md#login-challenges). Rate limited, fail-closed: `mfa-challenge:ip:<req.ip>` against
`config.rateLimiting.mfaChallenge` (5/15min default). It sets session cookies, so every browser
request is subject to the [CSRF origin check](middleware.md#csrf-origin-check) (403
`CSRF_ORIGIN_REJECTED` from an origin that is neither the issuer's nor in `cookies.trustedOrigins`).

**Verification order**: the challenge token is verified (signature, expiry, `type`, `iss` = the
issuer and `aud` = `<issuer>#mfa-challenge`); the user must be `ACTIVE` with MFA still
enabled; a challenge issued **before the account's last password change is void** (it was
earned with the old password); and the token carries the user's `sessionEpoch` as read before the
password was checked, so a "sign out everywhere" (password reset, logout-all, …) that lands between
the password step and this call refuses the challenge (401 `INVALID_MFA_CHALLENGE_TOKEN`). Then, under the [lockout](#per-account-lockout) (`method: 'totp'`,
counted before the code is checked): TOTP against `mfaSecret`, claiming its time step (single-use,
see above); **only if that fails**, the code is treated as a recovery code — normalized (upper-cased,
spaces and dashes removed, `O` read as `0` and `I`/`L` as `1`, so however it's typed off paper it
matches), HMAC'd bound to the user, and spent with one atomic
conditional update (`userRepository.consumeRecoveryCode(userId, codeHash)`), so two concurrent
requests can't both spend it. A spent recovery code is marked `usedAt: <now>` but **not removed**
from the array (kept for audit history). TOTP and recovery codes count against the same
per-account limit. The stored TOTP secret is opened first, so while `requireEncrypted` refuses a
plain-text secret (500 `MFA_SECRET_NOT_ENCRYPTED`) neither a TOTP code nor a recovery code gets
that user through. On success, a plain-text `mfaSecret` (only readable with `requireEncrypted:
false`) or one under a retired key is re-encrypted under the current key.

**A challenge token completes one login only.** Once the factor checks out, the token's `jti` is
claimed in the shared attempt-counter store (atomic, visible to every instance); presenting the
same token again — here or at `POST /webauthn/mfa/verify` — answers `INVALID_MFA_CHALLENGE_TOKEN`.

Wrong MFA codes do **not** count toward the password lockout (`password-login:<userId>`), so this
endpoint never triggers password login's lockout (`ACCOUNT_LOCKED` audit /
`onSuspiciousActivityDetected`). Conversely, a password-login lockout doesn't block this step — it
locks password login only, and the account stays `ACTIVE`. Brute
force here is stopped by the per-account MFA lockout, which has its own counter.

**Success**: sets session cookies + `200 { accessToken, accessTokenExpiresAt, refreshToken,
refreshTokenExpiresAt, userId }` — same shape as password login's non-MFA success (`refreshToken`
is in the body only as [`cookies.refreshTokenInBody`](bootstrap-config.md#cookiesrefreshtokeninbody)
allows — by default, only for non-browser clients). The new session's `auth_time`
is now, so it counts as a recent login for `requireRecentAuth()`.

Errors:
- `INVALID_MFA_CHALLENGE_TOKEN` (401) — thrown for several conditions that surface identically:
  the JWT itself is invalid/expired; it verifies but `mfaEnabled` has since been turned off; it
  was issued before the account's last password change; or it has already completed a login.
- `USER_NOT_ACTIVE` (403) — user not found, or not `ACTIVE` (e.g. an administrative lock).
- `CSRF_ORIGIN_REJECTED` (403) — a browser request from an untrusted origin.
- `INVALID_MFA_CODE` (400) — neither TOTP nor recovery code matched.
- `MFA_LOCKED` (429) — see [Per-account lockout](#per-account-lockout).
- `RATE_LIMIT_EXCEEDED` (429) / `RATE_LIMITER_UNAVAILABLE` (503) — the per-IP limit.
- `MFA_SECRET_UNREADABLE` / `MFA_SECRET_NOT_ENCRYPTED` / `MFA_ENCRYPTION_NOT_CONFIGURED` (500) —
  see [Secret encryption at rest](#secret-encryption-at-rest). No tokens are issued.

Hooks: `auditLog('MFA_VERIFIED', { userId, method })` (`method`: `'totp'` or `'recovery-code'`); `resolveAuthContext(user, { isNewUser: false,
method: 'mfa' })`; `onNewDeviceLogin` via `issueSession` if applicable.

## Per-account lockout

A per-**account** limit on failed second-factor attempts, shared by every place a code or assertion
is checked: TOTP and recovery codes at `POST /mfa/verify` (`method: 'totp'`), passkey-as-MFA at
`POST /webauthn/mfa/verify` (`'webauthn'`), the code at `POST /me/mfa/confirm`
(`'totp-enrolment'`), the password and code at `DELETE /me/mfa` (`'totp-disable'`), and the
password and code at `POST /me/mfa/recovery-codes` (`'recovery-codes'`). All count against one key per user
(`mfa:<userId>`), so guesses can't be spread across factors — or across IPs, which is all the
per-IP `rateLimiting.mfaChallenge` limit sees. Independent of `rateLimiting.enabled`.

```ts
config.mfa.lockout = { maxFailedAttempts: 5, windowSeconds: 900, lockSeconds: 900 } // defaults
```

- **Attempts are counted before the code is checked**, not after a failure: the counter's atomic
  increment is the gate, so a burst of concurrent requests gets exactly `maxFailedAttempts`
  guesses evaluated (0.3.0 checked first and counted after, so a parallel burst had every guess
  evaluated). A successful verify resets the count, so its reservation costs nothing; an attempt
  that fails for another reason (e.g. an expired WebAuthn challenge) keeps its reservation — when
  in doubt, it counts.
- The wrong guess that uses up the budget within `windowSeconds` locks the account's
  second-factor step for `lockSeconds`, and itself returns 429 `MFA_LOCKED` instead of the usual
  error. Failures older than the window don't accumulate.
- While locked, **every** attempt — including one with the correct code — gets 429 `MFA_LOCKED`
  with an identical body, before its code is looked at, so the response says nothing about whether
  it was right, and a recovery code submitted while locked isn't consumed.
- The lock lifts on its own after `lockSeconds`.
- On lockout, `onAuditLog` receives (once per lock, even under a concurrent burst)
  `{ action: 'MFA_LOCKED', userId, method, failedAttempts, lockedUntil, timestamp }` —
  `lockedUntil` is an ISO string. With webhooks configured it's also delivered as event
  `MFA_LOCKED`.

Counted in storage through the adapter's optional `attemptCounterRepository` (built-in Mongo: the
`IdpAttemptCounter` collection, TTL-indexed), so the limit holds across instances. An adapter
without one falls back to an in-process counter, with a startup warning. A counter backend error
fails closed (the request errors; nothing is verified). See
[Repository Adapters](repository-adapters.md#attemptcounterrepository-optional).

## Secret encryption at rest

`mfaSecret` and `mfaTempSecret` are encrypted with AES-256-GCM, stored as
`v1:<keyId>:<iv>:<ciphertext>:<tag>` (base64url parts). The owning user's id is bound as GCM
additional authenticated data, so a ciphertext copied onto another user's row fails to decrypt.

| `config.mfa.*` | Default | |
|---|---|---|
| `encryptionKey` | — | 32 bytes, base64 (`openssl rand -base64 32`). A bare string's key id is a 12-hex-char SHA-256 fingerprint of the key; pass `{ id, key }` to name it. Env: `IDP_MFA_ENCRYPTION_KEY`. |
| `previousEncryptionKeys` | `[]` | Retired keys, accepted for decryption only. Env: `IDP_MFA_PREVIOUS_ENCRYPTION_KEYS` (comma-separated). |
| `secretCipher` | — | Custom cipher (e.g. a KMS) — takes precedence over `encryptionKey`. See below. |
| `enabled` | `true` | `false`: no key needed; setup/confirm respond 404 `FEATURE_DISABLED`. Env: `IDP_MFA_ENABLED`. |
| `requireEncrypted` | `true` with `encryptionKey` or `secretCipher`, otherwise `false` | Refuse any remaining plain-text secret (500 `MFA_SECRET_NOT_ENCRYPTED`) instead of using it. Env: `IDP_MFA_REQUIRE_ENCRYPTED` (unset → this default). Before 0.4.0 the default was always `false`. |
| `allowPlaintext` | `false` | Development only: boot with MFA enabled and no key, storing secrets unencrypted; logs a loud warning. Env: `IDP_MFA_ALLOW_PLAINTEXT`. |

`initIdentityProvider()` throws if MFA is enabled with neither `encryptionKey` nor `secretCipher`
(unless `allowPlaintext`), if `requireEncrypted` is set without one, if a key isn't **exactly** the
base64 (or base64url) of 32 bytes (trailing garbage used to be ignored silently), or if
`secretCipher` lacks `encrypt`/`decrypt` — see
[Bootstrap & Configuration](bootstrap-config.md).

**Fails closed.** A secret that won't decrypt (tampered, wrong key, unknown key id) → 500
`MFA_SECRET_UNREADABLE`; an encrypted secret with no key configured → 500
`MFA_ENCRYPTION_NOT_CONFIGURED`. Neither is treated as "no secret", and no tokens are issued.

### Migrating from 0.2.x

Secrets written before 0.3.0 are plain base32 (so is anything written straight into the database).
Any stored value matching `/^[A-Z2-7]+=*$/i` is treated as plain text. With a key configured,
`requireEncrypted` defaults to `true` (since 0.4.0), so such a secret is refused — 500
`MFA_SECRET_NOT_ENCRYPTED`, and **that user can't complete MFA with a TOTP code, not even with a
recovery code** (a passkey second factor at `/webauthn/mfa/verify` still works) — until it is migrated. With
`requireEncrypted: false` set explicitly, it is still read and is re-encrypted on that user's next
successful `POST /mfa/verify`. To migrate them all at once:

```js
import { migrateMfaSecrets } from '@okeav/idp-core';

const { scanned, encrypted, reencrypted, failed } = await migrateMfaSecrets({ batchSize: 100, dryRun: false });
// failed: Array<{ userId, error }> — per-user errors are collected, not thrown
```

Call it after `initIdentityProvider()`, with a key configured (it throws otherwise). Encrypts every
plain-text `mfaSecret`/`mfaTempSecret` and re-encrypts any under a retired key. Idempotent, safe
while serving traffic, works with any storage adapter (uses only `countAll`, `findMany`,
`findById`, `updateById`). `dryRun: true` counts without writing.

Order when plain-text secrets may remain: set `encryptionKey` and `requireEncrypted: false` →
deploy → run `migrateMfaSecrets()` once → remove `requireEncrypted: false` (the default is then
`true`). Or run `migrateMfaSecrets()` against the database before the upgrade.

### Key rotation

1. Generate a new key and set it as `encryptionKey`; move the old one into
   `previousEncryptionKeys`. Deploy.
2. Let secrets re-encrypt lazily on each user's next successful verify, or run
   `migrateMfaSecrets()`.
3. Once `migrateMfaSecrets()` reports `reencrypted: 0` and an empty `failed`, drop the old key.

### Custom cipher (`secretCipher`)

```ts
interface SecretCipher {
  encrypt(plaintext: string, opts: { context: string }): string | Promise<string>;
  decrypt(ciphertext: string, opts: { context: string }): string | Promise<string>;
  needsRotation?(ciphertext: string): boolean; // true → re-encrypted on next successful verify / by migrateMfaSecrets()
}
```

`context` is the owning user's id — bind it to the ciphertext (e.g. as KMS encryption context).
`encrypt`'s output is stored verbatim and **must not look like bare base32** — that shape marks a
legacy plain-text secret. A prefix such as `kms:` is enough. An `encrypt` result that is empty or
looks like bare base32 is refused (500 `MFA_SECRET_UNREADABLE`) rather than stored. The built-in cipher is exported as
`AesGcmSecretCipher({ currentKey, previousKeys? })` for advanced use.

## Storage methods

Two optional, atomic `UserRepository` methods back the single-use guarantees above (the built-in
Mongo adapter implements both, and users gain an `mfaLastTotpStep` field):

- `claimTotpStep(userId, step)` → `boolean` — records `step` as the last accepted TOTP step only if
  it's later than the stored one; false otherwise.
- `consumeRecoveryCode(userId, codeHash)` → `boolean` — marks the unused recovery code with this
  hash `usedAt: now` in one conditional update; false if there is none.

An adapter without them still works: a non-atomic read-then-write fallback is used (correct for
sequential requests, racy under concurrency) and `initIdentityProvider()` logs a startup warning.
Challenge-token single use is recorded through the `attemptCounterRepository` (or its in-process
fallback). See [Repository Adapters](repository-adapters.md).

## Related

- [Password & Email Auth](password-email-auth.md) — issues the `mfaChallengeToken` this flow
  consumes; shares `issueSession`/cookie mechanics.
- [WebAuthn](webauthn.md) — passkey-as-MFA is an alternative second factor to this TOTP flow,
  consuming the same `mfaChallengeToken`.
- [Tokens & Signing (RS256)](tokens-rs256.md) — `issueMfaChallengeToken`/`verifyMfaChallengeToken`.
- [Errors](errors.md) — `MFA_LOCKED` and the `MFA_SECRET_*` codes.
- [MFA TOTP Setup & Verify example](../examples/mfa-totp-setup-and-verify.md)
