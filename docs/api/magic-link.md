---
title: "Magic Link (Passwordless Email Login)"
package: "@okeav/idp-core"
category: "api-reference"
tags: ["auth", "magic-link", "passwordless"]
description: "requestMagicLinkHandler and verifyMagicLinkHandler — single-use, time-limited email login links."
---

# Magic Link (Passwordless Email Login)

`requestMagicLinkHandler` / `verifyMagicLinkHandler` implement a single-use, time-limited
(`config.ttls.magicLink`, default 900s/15min) email login link, built on the same
`VerificationTokenRepository` used for email verification and password reset (no separate
storage — see [Repository Adapters](repository-adapters.md)).

## Routes (via `buildRouter()`, unless `features.magicLink: false`)

| Method | Path | Auth | Schema |
|---|---|---|---|
| POST | `/magic-link/request` | none | `requestMagicLinkSchema` |
| POST | `/magic-link/verify` | none | `verifyMagicLinkSchema` |

## `requestMagicLinkHandler`

**Body**: `{ email: string }` (trimmed, lowercased, valid-email, max 255 chars).

**Rate limited**, both fail-closed (a rate-limiter backend error → 503 `RATE_LIMITER_UNAVAILABLE`):
- per IP — `magic-link:ip:<ip>` against `config.rateLimiting.magicLink` (default 3/hour);
- per address — `magic-link:email:<keyed hash of the email>` against
  `config.rateLimiting.magicLinkByEmail` (default 3/hour), so a distributed sender can't flood one
  inbox. The key holds the email's keyed hash, never the plain address.

Over either limit → 429 `RATE_LIMIT_EXCEEDED`. IPv6 clients are keyed by their /64.

**Always responds** `{ status: 'ok' }` (enumeration-safe) regardless of whether the email belongs
to an existing account, a newly-created one, or neither.

Behavior by email state:
- **Unknown email, `config.magicLink.allowSignupViaMagicLink` true (default)**: creates a new user
  in `PENDING_VERIFICATION` status — the same starting state password registration uses — and
  issues a link. `verifyMagicLinkHandler` promotes it to `ACTIVE` on first successful click,
  mirroring the register→verify-email flow but collapsed into one link instead of two steps.
- **Unknown email, `allowSignupViaMagicLink: false`**: no-ops — no user created, no token issued,
  no hook fired. Use this for invite-only apps where an unrecognized email should silently do
  nothing.
- **Existing user with status `DELETED`**: no-ops — a magic link never resurrects a soft-deleted
  account.
- **Any other existing user**: issues a link regardless of current status (e.g. an administratively
  `LOCKED` account still gets a link issued here — the status gate happens at *verify* time, via
  `assertUsableStatus`, not at request time).

**Token**: 32 raw bytes (`generateOpaqueToken(32)` → 64 hex chars), hashed at rest with HMAC-SHA256
(under the magic-link key derived from `config.security.tokenHashSecret` — see
[Opaque-token hashing](tokens-rs256.md#opaque-token-hashing)) under `verificationTokenRepository`
type `'magic_link'`.
**Only the newest link works**: issuing one replaces the account's magic-link token atomically
(`verificationTokenRepository.replaceForUser('magic_link', userId, …)`, backed by a partial unique
index — one live link per user even under concurrent requests).

**Hooks fired**: `auditLog('MAGIC_LINK_REQUESTED', { userId, email, isNewUser })`, then
`onMagicLinkRequested({ email, magicLinkToken: <raw token>, firstName?, lastName?, isNewUser })` —
the hook is where you embed the raw token into an emailed link (this package never sends email
itself). Both are **started but not awaited**: waiting for an email to be sent would make the
response measurably slower for a real account than for an unknown address. Errors are logged, not
returned. In a serverless runtime, make the hook hand off quickly (enqueue rather than send inline).

With [webhooks](webhooks.md) configured, `magicLinkToken` is **stripped** from the
`onMagicLinkRequested` delivery unless the endpoint sets `includeCredentials: true` — set that
only on the endpoint that sends your emails.

## `verifyMagicLinkHandler`

**Body**: `{ token: string }`.

Sets session cookies, so every browser request is subject to the
[CSRF origin check](middleware.md#csrf-origin-check): an `Origin` that is neither the issuer's nor
in `cookies.trustedOrigins` gets 403 `CSRF_ORIGIN_REJECTED` (login CSRF). Non-browser clients are
unaffected.

Consumes the token (`verificationTokenRepository.consumeByHash('magic_link', ...)` — single-use,
deleted/marked-used on read) and issues a full session through the **exact same
`resolveAuthContext` → `issueSession` path every other login method uses** — magic-link login is
not a shortcut around claims resolution.

- If the token belongs to a `PENDING_VERIFICATION` user (the signup-via-magic-link case, or an
  account registered with a password but never verified), promotes it to `ACTIVE` (also resetting
  `failedLoginAttempts`/`lockUntil` and `registrationContested`) and treats this as `isNewUser: true` for
  `resolveAuthContext`'s `ctx`. **Any password and MFA state set before the address was proven are
  discarded** (`passwordHash: null`, `mfaEnabled: false`, secrets and recovery codes cleared), and
  outstanding email-verification codes are deleted: clicking the link proves ownership of the
  inbox, not of a password anyone could have pre-registered against the victim's address. The
  owner can set a password through password reset. The activation is conditional on the account
  still being pending (`userRepository.updateByIdIfStatus`): if it was activated meanwhile (with
  the password its owner verified), nothing is wiped — it's then an ordinary sign-in, through
  `assertUsableStatus`.
- Otherwise runs `assertUsableStatus(user)` — an administratively `LOCKED` (no `lockUntil`) or
  `SUSPENDED`/etc. account rejects here even though the request step let the link be issued (see
  above). A failed-password lockout does **not** block a magic link: it locks password login only.
  It also isn't lifted by it (the password-guessing budget stays spent until it expires or a
  password reset); only a lock recorded before 0.4.0 (`failedLoginAttempts`/`lockUntil`) is cleared
  by the login.

**MFA.** A magic link is one factor (the inbox). If the account has MFA enabled, no session is
issued and no cookies are set; the response is the same MFA challenge password login returns:

```json
{ "mfaRequired": true, "mfaChallengeToken": "...", "expiresIn": 300 }
```

Complete it at `POST /mfa/verify` (TOTP or recovery code) or `POST /webauthn/mfa/verify`
(passkey) — see [MFA](mfa.md). `expiresIn` is `config.ttls.mfaChallenge` in seconds. Audit event:
`MAGIC_LINK_MFA_REQUIRED` (`{ userId }`).

**Success (200)** (no MFA):
```json
{
  "accessToken": "...", "accessTokenExpiresAt": "...",
  "refreshToken": "...", "refreshTokenExpiresAt": "...",
  "userId": "...", "isNewUser": true
}
```
Also sets the session cookies (`__Host-access_token`/`__Host-refresh_token` — same names and `cookieOptions()` as every other login
method — see [Password & Email Auth](password-email-auth.md)). `refreshToken` is in the body only
as [`cookies.refreshTokenInBody`](bootstrap-config.md#cookiesrefreshtokeninbody) allows — by
default, only for non-browser clients.

**Errors**:
- `INVALID_OR_EXPIRED_TOKEN` (400) — token not found, already used, or expired.
- `CSRF_ORIGIN_REJECTED` (403) — a browser request from an untrusted origin (see above).
- `USER_NOT_FOUND` (404) — the token's linked user no longer exists (edge case).
- A `PENDING_VERIFICATION` user is always the "new user" case — it's consumed by the
  activate-and-continue path above `assertUsableStatus`, so `PENDING_VERIFICATION`/`INVITED` (403)
  can never actually be thrown here. For any other non-`ACTIVE` status, whatever
  `assertUsableStatus` throws: `ACCOUNT_LOCKED` (423, administrative lock only), `ACCOUNT_SUSPENDED` (403, also covers
  `DISABLED`), `INVALID_CREDENTIALS` (401, `DELETED` — reachable if the token was issued before the
  account was soft-deleted), or `USER_NOT_ACTIVE` (403, any other unrecognized status) — see
  [Errors](errors.md).

**Hooks fired**: `auditLog('MAGIC_LINK_LOGIN', { userId, isNewUser })`, plus
`resolveAuthContext(user, { isNewUser, method: 'magic_link' })` and (via `issueSession`)
`onNewDeviceLogin` if applicable.

## Related

- [Password & Email Auth](password-email-auth.md) — the shared `issueSession`/cookie mechanics.
- [Repository Adapters](repository-adapters.md) — `VerificationTokenRepository`.
- [MFA](mfa.md) — completing the `mfaRequired` challenge.
- [Webhooks](webhooks.md) — credential stripping and `includeCredentials`.
- [Rate Limiter Interface](rate-limiter-interface.md)
- [Magic Link with Express example](../examples/magic-link-with-express.md)
