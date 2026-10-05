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

Secrets are encrypted at rest and failed codes count toward a per-account lockout — see
[Secret encryption at rest](#secret-encryption-at-rest) and
[Per-account lockout](#per-account-lockout) below. With `config.mfa.enabled: false`, setup and
confirm respond 404 `FEATURE_DISABLED`.

> Every handler here except `verifyMfaChallengeHandler` reads `req.auth.userId` directly with no
> explicit `UNAUTHENTICATED` guard — they rely on `authContextMiddleware()` being mounted in front
> of them (as `buildRouter()` does). If you wire these handlers individually, mount
> `authContextMiddleware()` first or a raw `TypeError` will propagate instead of a structured
> `IdpError`.

## `GET /me/mfa` — `getMfaStatusHandler`

No body. → `{ mfaEnabled: boolean }`. `USER_NOT_FOUND` (404).

## `POST /me/mfa/setup` — `setupMfaHandler`

No body. Generates a new TOTP secret and stores it, encrypted, in `mfaTempSecret` **only** — `mfaEnabled`
stays `false` and the confirmed `mfaSecret` is untouched until `confirmMfaHandler` succeeds.
Calling setup again before confirming simply overwrites `mfaTempSecret` (no error on repeat calls
while `mfaEnabled` is still false).

→ `{ secret, otpauthUrl }` — `otpauthUrl` is a raw `otplib`-generated `otpauth://` URI
(`label: user.email, issuer: config.mfa.issuerLabel, strategy: 'totp'`). **This package does not
render a QR code** — render one client-side from `otpauthUrl`.

Errors: `FEATURE_DISABLED` (404, `mfa.enabled: false`); `USER_NOT_FOUND` (404);
`MFA_ALREADY_ENABLED` (400).

## `POST /me/mfa/confirm` — `confirmMfaHandler`

Body: `{ code: string (6-10 chars) }`. Verifies `code` against `mfaTempSecret`, under the
[per-account lockout](#per-account-lockout) (`method: 'totp-enrolment'`). On success: re-encrypts
the temp secret into `mfaSecret` (a legacy plain-text temp secret is sealed here), nulls
`mfaTempSecret`, sets `mfaEnabled: true`, and
**generates recovery codes at this point** (not at setup time) — count from
`config.mfa.recoveryCodeCount` (default 10). Each code: two 3-byte hex groups joined by a hyphen
(`XXXXXX-XXXXXX`). Stored server-side only as `{ codeHash: HMAC-SHA256(code), usedAt: null }` —
raw codes are never persisted.

→ `{ mfaEnabled: true, recoveryCodes: [...] }` — **shown once, in plaintext.** Your UI must prompt
the user to save these; there's no way to retrieve them again short of regenerating (which
invalidates the old set).

Errors: `FEATURE_DISABLED` (404); `USER_NOT_FOUND` (404); `MFA_ALREADY_ENABLED` (400);
`MFA_SETUP_REQUIRED` (400, no `mfaTempSecret` present — call setup first); `INVALID_MFA_CODE`
(400); `MFA_LOCKED` (429); the [secret-read errors](#secret-encryption-at-rest) (500).

## `DELETE /me/mfa` — `disableMfaHandler`

Body: `{ password: string, code: string (6-10 chars) }`. Runs under the
[per-account lockout](#per-account-lockout) (`method: 'totp-disable'`): the lock is checked
**before** the password, so a locked account can't be used as a password oracle; then the
password, then the TOTP code. Only a wrong code counts as a failure, not a wrong password. Fully resets MFA state: `mfaEnabled: false, mfaSecret: null, mfaTempSecret: null,
mfaRecoveryCodes: []` — all recovery codes are discarded too, not just the submitted TOTP.

→ `{ mfaEnabled: false }`.

Errors: `USER_NOT_FOUND` (404); `MFA_NOT_ENABLED` (400); `CURRENT_PASSWORD_INCORRECT` (400);
`INVALID_MFA_CODE` (400); `MFA_LOCKED` (429); the [secret-read errors](#secret-encryption-at-rest)
(500).

## `POST /me/mfa/recovery-codes` — `regenerateRecoveryCodesHandler`

Body: `{ password: string }` — **no TOTP code required**, password alone. Fully replaces
`mfaRecoveryCodes` (old codes, used or unused, are invalidated wholesale).

→ `{ recoveryCodes: [...] }` (plaintext, shown once, same generation scheme as confirm).

Errors: `USER_NOT_FOUND` (404); `MFA_NOT_ENABLED` (400); `CURRENT_PASSWORD_INCORRECT` (400).

## `POST /mfa/verify` — `verifyMfaChallengeHandler`

**No auth required** — identity comes from the challenge token, not `req.auth`. Completes the
`mfaRequired` response `loginHandler` returns when `user.mfaEnabled`. Body:
`{ mfaChallengeToken: string, code: string (6-32 chars) }` — a TOTP code or a recovery code
(`XXXXXX-XXXXXX`, 13 chars). Rate limited, fail-closed: `mfa-challenge:ip:<req.ip>` against
`config.rateLimiting.mfaChallenge` (5/15min default).

**Verification order**: [lockout](#per-account-lockout) check (`method: 'totp'`); TOTP against
`mfaSecret`; **only if that fails**, a scan of `mfaRecoveryCodes` for an unused entry (`usedAt`
falsy) whose hash (`crypto.timingSafeEqual`, length-checked first) matches the submitted code. A
matched recovery code is marked `usedAt: <now>` but **not removed** from the array (kept for audit
history). TOTP and recovery codes count against the same per-account limit. On success, a
plain-text `mfaSecret` (or one under a retired key) is re-encrypted under the current key.

On **total failure** (neither TOTP nor any recovery code matched), the handler also calls
`incrementFailedLoginAttempts` — but never checks the result against `maxFailedLoginAttempts`, so
this endpoint never triggers password login's `ACCOUNT_LOCKED`/`onSuspiciousActivityDetected`.
Brute force here is stopped by the per-account MFA lockout instead.

**Success**: sets session cookies + `200 { accessToken, accessTokenExpiresAt, refreshToken,
refreshTokenExpiresAt, userId }` — same shape as password login's non-MFA success.

Errors:
- `INVALID_MFA_CHALLENGE_TOKEN` (401) — thrown for two different conditions that surface
  identically: the JWT itself is invalid/expired, **or** it verifies fine but `mfaEnabled` has
  since been turned off (e.g. disabled between challenge issuance and this call).
- `USER_NOT_ACTIVE` (403) — user not found, or not `ACTIVE`.
- `INVALID_MFA_CODE` (400) — neither TOTP nor recovery code matched.
- `MFA_LOCKED` (429) — see [Per-account lockout](#per-account-lockout).
- `RATE_LIMIT_EXCEEDED` (429) / `RATE_LIMITER_UNAVAILABLE` (503) — the per-IP limit.
- `MFA_SECRET_UNREADABLE` / `MFA_SECRET_NOT_ENCRYPTED` / `MFA_ENCRYPTION_NOT_CONFIGURED` (500) —
  see [Secret encryption at rest](#secret-encryption-at-rest). No tokens are issued.

Hooks: `auditLog('MFA_VERIFIED', { userId })`; `resolveAuthContext(user, { isNewUser: false,
method: 'mfa' })`; `onNewDeviceLogin` via `issueSession` if applicable.

## Per-account lockout

A per-**account** limit on failed second-factor attempts, shared by every place a code or assertion
is checked: TOTP and recovery codes at `POST /mfa/verify` (`method: 'totp'`), passkey-as-MFA at
`POST /webauthn/mfa/verify` (`'webauthn'` — a failed or unknown-credential assertion counts; an
expired/missing challenge doesn't), the code at `POST /me/mfa/confirm` (`'totp-enrolment'`), and
the code at `DELETE /me/mfa` (`'totp-disable'`). All count against one key per user
(`mfa:<userId>`), so guesses can't be spread across factors — or across IPs, which is all the
per-IP `rateLimiting.mfaChallenge` limit sees. Independent of `rateLimiting.enabled`.

```ts
config.mfa.lockout = { maxFailedAttempts: 5, windowSeconds: 900, lockSeconds: 900 } // defaults
```

- The failure that reaches `maxFailedAttempts` within `windowSeconds` locks the account's
  second-factor step for `lockSeconds`, and itself returns 429 `MFA_LOCKED` instead of the usual
  error. Failures older than the window don't accumulate.
- While locked, **every** attempt — including one with the correct code — gets 429 `MFA_LOCKED`
  with an identical body. The lock is checked before the code is evaluated, so the response says
  nothing about whether it was right, and a recovery code submitted while locked isn't consumed.
- A successful verify resets the counter. The lock lifts on its own after `lockSeconds`.
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
| `requireEncrypted` | `false` | Refuse any remaining plain-text secret (500 `MFA_SECRET_NOT_ENCRYPTED`) instead of using it. Env: `IDP_MFA_REQUIRE_ENCRYPTED`. |
| `allowPlaintext` | `false` | Development only: boot with MFA enabled and no key, storing secrets unencrypted; logs a loud warning. Env: `IDP_MFA_ALLOW_PLAINTEXT`. |

`initIdentityProvider()` throws if MFA is enabled with neither `encryptionKey` nor `secretCipher`
(unless `allowPlaintext`), if `requireEncrypted` is set without one, if a key doesn't decode to 32
bytes, or if `secretCipher` lacks `encrypt`/`decrypt` — see
[Bootstrap & Configuration](bootstrap-config.md).

**Fails closed.** A secret that won't decrypt (tampered, wrong key, unknown key id) → 500
`MFA_SECRET_UNREADABLE`; an encrypted secret with no key configured → 500
`MFA_ENCRYPTION_NOT_CONFIGURED`. Neither is treated as "no secret", and no tokens are issued.

### Migrating from 0.2.x

Secrets written before 0.3.0 are plain base32. Any stored value matching `/^[A-Z2-7]+=*$/i` is
treated as plain text and still read (unless `requireEncrypted`), and is re-encrypted on that
user's next successful `POST /mfa/verify`. To do them all at once:

```js
import { migrateMfaSecrets } from '@okeav/idp-core';

const { scanned, encrypted, reencrypted, failed } = await migrateMfaSecrets({ batchSize: 100, dryRun: false });
// failed: Array<{ userId, error }> — per-user errors are collected, not thrown
```

Call it after `initIdentityProvider()`, with a key configured (it throws otherwise). Encrypts every
plain-text `mfaSecret`/`mfaTempSecret` and re-encrypts any under a retired key. Idempotent, safe
while serving traffic, works with any storage adapter (uses only `countAll`, `findMany`,
`findById`, `updateById`). `dryRun: true` counts without writing.

Order: set `encryptionKey` → deploy → run `migrateMfaSecrets()` once → set
`requireEncrypted: true`.

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
legacy plain-text secret. A prefix such as `kms:` is enough. The built-in cipher is exported as
`AesGcmSecretCipher({ currentKey, previousKeys? })` for advanced use.

## Related

- [Password & Email Auth](password-email-auth.md) — issues the `mfaChallengeToken` this flow
  consumes; shares `issueSession`/cookie mechanics.
- [WebAuthn](webauthn.md) — passkey-as-MFA is an alternative second factor to this TOTP flow,
  consuming the same `mfaChallengeToken`.
- [Tokens & Signing (RS256)](tokens-rs256.md) — `issueMfaChallengeToken`/`verifyMfaChallengeToken`.
- [Errors](errors.md) — `MFA_LOCKED` and the `MFA_SECRET_*` codes.
- [MFA TOTP Setup & Verify example](../examples/mfa-totp-setup-and-verify.md)
