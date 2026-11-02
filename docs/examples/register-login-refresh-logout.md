---
title: "Register, Verify, Login, Refresh, Logout"
package: "@okeav/idp-core"
category: "example"
tags: ["auth", "password", "sessions", "express"]
description: "The full password-auth lifecycle against a running idp-core server, including the token-refresh rotation cycle."
---

# Register, Verify, Login, Refresh, Logout

The complete password-based session lifecycle, using `fetch` against a server built with
[buildRouter()](quickstart-express.md) mounted at `/auth`, with `idpErrorHandler()` mounted after
it (so failures come back as `{ error, message }`).

## Prerequisites

- A running idp-core server (see [Quickstart: Express Server](quickstart-express.md)).
- Node's built-in `fetch` (Node ≥ 18) with cookie handling, or run these as `curl` calls with
  `-c cookies.txt -b cookies.txt` to persist cookies across requests.
- For a **browser** frontend on another origin: list that origin in the server's
  `cookies.trustedOrigins` (`IDP_COOKIE_TRUSTED_ORIGINS`). Cookie-authenticated
  `POST`/`PATCH`/`DELETE` requests from any other origin get 403 `CSRF_ORIGIN_REJECTED` (see
  [Middleware](../api/middleware.md#csrf-origin-check)) — and so does **every** browser request to
  `/login`, `/session/refresh` and `/session/logout` (they set or clear session cookies), even from a frontend that uses Bearer tokens.
  Non-browser clients are unaffected.

## Register + verify

```js
const BASE = 'http://localhost:3000/auth';

async function register(email, password) {
  // Password: 8–128 characters and at most 72 bytes (UTF-8), with upper/lowercase, a digit and a
  // special character — otherwise 400 VALIDATION_ERROR.
  const res = await fetch(`${BASE}/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
    credentials: 'include', // keeps the verification-ticket cookie for verifyEmail()
  });
  // Always { status: 'ok', verificationTicket } — enumeration-safe: a ticket for the address, issued
  // the same way whether or not it has an account (see password-email-auth.md). A client without
  // cookies keeps verificationTicket.
  return res.json();
}

// The verification code is printed to the server console by the
// onVerificationEmailRequested hook — in a real app you'd email it instead.
// `password` is needed only when the address was registered more than once before verification.
// `ticket` (the verificationTicket register() returned) is needed only by a client without cookies;
// a browser sends the ticket cookie.
async function verifyEmail(email, code, { password, ticket } = {}) {
  const res = await fetch(`${BASE}/register/verify-email`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, code, ...(password ? { password } : {}), ...(ticket ? { ticket } : {}) }),
    credentials: 'include',
  });
  // 400 INVALID_OR_EXPIRED_TOKEN, 400 REGISTRATION_PASSWORD_REQUIRED (ask for the password and
  // retry with the same code), or 429 VERIFICATION_LOCKED
  if (!res.ok) throw await res.json();
  return res.json(); // { status: 'ok', userId, email }
}
```

`/register/verify-email` answers 400 `INVALID_OR_EXPIRED_TOKEN` for a wrong code, an unknown
address **and an address that's already verified** — so a second click on a used link is a 400,
not `ok`. Wrong 6-digit codes are budgeted: 5 per verification ticket (the one `register()` or
resend handed out for the address), and 5 per address for attempts without a ticket — each per
24 hours, then 429 `VERIFICATION_LOCKED` for 24 hours — and 20 wrong codes per address in all, after
which only the link works. At most 3 codes are sent per address per code lifetime; later emails
carry only the link, so your verify page should handle a `token` too. So a stranger guessing at the address can lock out
ticketless attempts, but not the browser that registered. A spent budget doesn't clear the code,
and the emailed **link** (`token`) always works — point the user at it, or have them request a new
code (and ticket) with `POST /register/resend-verification { email }` (always `{ status: 'ok',
verificationTicket }`).

A completed password reset (`/password/forgot` → `/password/reset`) also verifies a pending
account: it proved the inbox, so the account becomes `ACTIVE` with the new password and its
outstanding verification codes are deleted.

Registering again with an address that's still pending sends a fresh code bound to the new
registration's password; earlier codes keep working, each bound to its own registration's
password. From then on the address is *contested*: `/register/verify-email` answers 400
`REGISTRATION_PASSWORD_REQUIRED` unless the body also carries the `password` of the registration
the code came from (the code stays usable — ask for the password and retry); a wrong password
answers 400 `INVALID_OR_EXPIRED_TOKEN`, the same as a wrong code. Verifying activates
that password. This is what stops someone who registers your address first (or right after you)
from having you activate *their* password.

## Login (cookie-based)

```js
async function login(email, password) {
  const res = await fetch(`${BASE}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
    credentials: 'include', // keep the session cookies
  });
  // 401 INVALID_CREDENTIALS — also while password login is locked (5 wrong passwords per 30 min,
  // by default), and for a not-yet-verified account
  if (!res.ok) throw await res.json();
  const body = await res.json();
  if (body.mfaRequired) {
    // See mfa-totp-setup-and-verify.md — complete via POST /auth/mfa/verify
    // with { mfaChallengeToken: body.mfaChallengeToken, code }.
    return { mfaRequired: true, mfaChallengeToken: body.mfaChallengeToken };
  }
  return body; // { accessToken, accessTokenExpiresAt, refreshTokenExpiresAt, userId } (+ refreshToken for non-browser clients)
}
```

`loginHandler` sets the session as `httpOnly` cookies — `__Host-access_token` (`Path=/`),
`__Secure-refresh_token` (`Path=/auth/session`, sent only to the session endpoints) and its
`__Host-refresh_binding` (`Path=/`); `__Secure-…` when `cookies.domain` is set; plain names only
without `Secure`, e.g. under `NODE_ENV=development` (see
[Password & Email Auth](../api/password-email-auth.md#shared-session-mechanics)).
A browser client typically only needs `credentials: 'include'` and never touches the token strings
directly — and since they're `httpOnly`, frontend code can't read them by any name (if yours
checked for an `access_token` cookie to decide whether the user is signed in, call `GET /me`
instead). By default (`cookies.refreshTokenInBody: 'auto'`) a browser request — one carrying
`Origin` or `Sec-Fetch-Site`, as browsers send on these POSTs — gets no `refreshToken` in the JSON
body, so page script can never read it; the refresh cookie carries it. A non-browser client (a
mobile app, a service) sends neither header, so it gets `refreshToken` in the body, reads
`accessToken`/`refreshToken` from there, and sends the access token as
`Authorization: Bearer <token>` on subsequent calls. A browser app that has to keep the refresh
token itself sets `refreshTokenInBody: true` on the server (`false` never includes it).

## Authenticated request

```js
async function getMe(accessToken) {
  const res = await fetch(`${BASE}/me`, {
    headers: { Authorization: `Bearer ${accessToken}` },
    // or, for a cookie-based client: credentials: 'include' with no header
  });
  if (!res.ok) throw await res.json(); // { error: <ERROR_CODE>, message }
  return res.json(); // { userId, email, emailVerified, isActive, status, mfaEnabled, profile, createdAt, updatedAt }
}
```

A few sensitive routes — `DELETE /me`, passkey registration and deletion, MFA setup/confirm —
also need a **recent login** (default within 15 minutes). Otherwise they answer 401
`REAUTHENTICATION_REQUIRED`: send the user through `login()` again and retry with the new token.
A refreshed token doesn't count — it keeps the original login time.

## Refresh

```js
async function refresh(refreshToken) {
  const res = await fetch(`${BASE}/session/refresh`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    // Non-browser clients send the token; browser clients send {} and rely on the cookie.
    // (A token in the body wins over the cookie.)
    body: JSON.stringify(refreshToken ? { refreshToken } : {}),
    credentials: 'include',
  });
  if (!res.ok) throw await res.json(); // 401 INVALID_REFRESH_TOKEN → log in again
  return res.json(); // a NEW accessToken (+ the new refreshToken for non-browser clients — see above)
}
```

Every refresh **rotates** the refresh token — the old one stops working immediately (see
[Password & Email Auth](../api/password-email-auth.md#refresh--logout)). Store the new
`refreshToken` from the response and discard the old one. Don't retry a refresh with a stale
token: within 10 seconds of its rotation it's merely refused (two tabs refreshing at once), but
after that, presenting an already-rotated token is treated as theft and **revokes the whole
session** — every token from that login — so the user has to log in again.

A refresh that's refused (e.g. the account was suspended) doesn't burn the token — every check runs
before it is consumed — so retrying the same token afterwards is not mistaken for theft. A
failed-password lockout doesn't affect refresh at all: it locks password login only.

Refreshing also doesn't keep a session alive forever: 90 days after the login
(`session.absoluteLifetimeSeconds`) `/session/refresh` answers 401 `INVALID_REFRESH_TOKEN` regardless.
Each refresh re-runs `resolveAuthContext`, so the new access token carries current claims.

## Logout

```js
async function logout(refreshToken) {
  const res = await fetch(`${BASE}/session/logout`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    // Browser clients can omit the token: the handler falls back to the
    // httpOnly refresh cookie (credentials: 'include' sends it). A browser call must
    // come from the issuer's origin or one in cookies.trustedOrigins (CSRF check).
    body: JSON.stringify(refreshToken ? { refreshToken } : {}),
    credentials: 'include',
  });
  return res.json(); // { status: 'ok' } — the session cookies are cleared
}

// Revoke every session for this user (all devices) instead of just one:
async function logoutEverywhere(accessToken) {
  const res = await fetch(`${BASE}/session/logout/all`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  return res.json(); // { status: 'ok' }
}
```

## Related

- [Password & Email Auth](../api/password-email-auth.md) — full handler reference.
- [Errors](../api/errors.md) — the `error`/`message` shape on failed responses.
- [Session Management example](session-management.md) — listing/revoking individual sessions.
- [MFA TOTP Setup & Verify example](mfa-totp-setup-and-verify.md) — completing an `mfaRequired` login.
