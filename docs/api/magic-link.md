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

## Routes (via `buildRouter()`)

| Method | Path | Auth | Schema |
|---|---|---|---|
| POST | `/magic-link/request` | none | `requestMagicLinkSchema` |
| POST | `/magic-link/verify` | none | `verifyMagicLinkSchema` |

## `requestMagicLinkHandler`

**Body**: `{ email: string }` (trimmed, lowercased, valid-email, max 255 chars).

**Rate limited**: `magic-link:ip:<req.ip>` against `config.rateLimiting.magicLink` (default 3/hour).

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
- **Any other existing user**: issues a link regardless of current status (e.g. a `LOCKED` account
  still gets a link issued here — the status gate happens at *verify* time, via
  `assertUsableStatus`, not at request time).

**Token**: 32 raw bytes (`generateOpaqueToken(32)` → 64 hex chars), hashed at rest with HMAC-SHA256
(`config.security.tokenHashSecret`) under `verificationTokenRepository` type `'magic_link'`.

**Hooks fired**: `auditLog('MAGIC_LINK_REQUESTED', { userId, email, isNewUser })`, then
`onMagicLinkRequested({ email, magicLinkToken: <raw token>, firstName?, lastName?, isNewUser })` —
the hook is where you embed the raw token into an emailed link (this package never sends email
itself).

## `verifyMagicLinkHandler`

**Body**: `{ token: string }`.

Consumes the token (`verificationTokenRepository.consumeByHash('magic_link', ...)` — single-use,
deleted/marked-used on read) and issues a full session through the **exact same
`resolveAuthContext` → `issueSession` path every other login method uses** — magic-link login is
not a shortcut around claims resolution.

- If the token belongs to a `PENDING_VERIFICATION` user (the signup-via-magic-link case), promotes
  it to `ACTIVE` (also resetting `failedLoginAttempts`/`lockUntil`) and treats this as `isNewUser:
  true` for `resolveAuthContext`'s `ctx`.
- Otherwise runs `assertUsableStatus(user)` — a `LOCKED`/`SUSPENDED`/etc. account rejects here even
  though the request step let the link be issued (see above).

**Success (200)**:
```json
{
  "accessToken": "...", "accessTokenExpiresAt": "...",
  "refreshToken": "...", "refreshTokenExpiresAt": "...",
  "userId": "...", "isNewUser": true
}
```
Also sets the `access_token`/`refresh_token` cookies (same `cookieOptions()` as every other login
method — see [Password & Email Auth](password-email-auth.md)).

**Errors**:
- `INVALID_OR_EXPIRED_TOKEN` (400) — token not found, already used, or expired.
- `USER_NOT_FOUND` (404) — the token's linked user no longer exists (edge case).
- A `PENDING_VERIFICATION` user is always the "new user" case — it's consumed by the
  activate-and-continue path above `assertUsableStatus`, so `PENDING_VERIFICATION`/`INVITED` (403)
  can never actually be thrown here. For any other non-`ACTIVE` status, whatever
  `assertUsableStatus` throws: `ACCOUNT_LOCKED` (423), `ACCOUNT_SUSPENDED` (403, also covers
  `DISABLED`), `INVALID_CREDENTIALS` (401, `DELETED` — reachable if the token was issued before the
  account was soft-deleted), or `USER_NOT_ACTIVE` (403, any other unrecognized status) — see
  [Errors](errors.md).

**Hooks fired**: `auditLog('MAGIC_LINK_LOGIN', { userId, isNewUser })`, plus
`resolveAuthContext(user, { isNewUser, method: 'magic_link' })` and (via `issueSession`)
`onNewDeviceLogin` if applicable.

## Related

- [Password & Email Auth](password-email-auth.md) — the shared `issueSession`/cookie mechanics.
- [Repository Adapters](repository-adapters.md) — `VerificationTokenRepository`.
- [Rate Limiter Interface](rate-limiter-interface.md)
- [Magic Link with Express example](../examples/magic-link-with-express.md)
