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
- For a **browser** frontend on another origin that uses the session cookies: list that origin in
  the server's `cookies.trustedOrigins` (`IDP_COOKIE_TRUSTED_ORIGINS`). Cookie-authenticated
  `POST`/`PATCH`/`DELETE` requests from any other origin get 403 `CSRF_ORIGIN_REJECTED` (see
  [Middleware](../api/middleware.md#csrf-origin-check)). Bearer-token clients are unaffected.

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
  });
  return res.json(); // always { status: 'ok' } — enumeration-safe, see password-email-auth.md
}

// The verification code is printed to the server console by the
// onVerificationEmailRequested hook — in a real app you'd email it instead.
async function verifyEmail(email, code) {
  const res = await fetch(`${BASE}/register/verify-email`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, code }),
  });
  if (!res.ok) throw await res.json(); // 400 INVALID_OR_EXPIRED_TOKEN, or 429 VERIFICATION_LOCKED
  return res.json(); // { status: 'ok', userId, email }
}
```

`/register/verify-email` answers 400 `INVALID_OR_EXPIRED_TOKEN` for a wrong code, an unknown
address **and an address that's already verified** — so a second click on a used link is a 400,
not `ok`. After 5 wrong codes (per account, per hour) every outstanding code is deleted and the
endpoint answers 429 `VERIFICATION_LOCKED`; have the user request a new one with
`POST /register/resend-verification { email }` (always `{ status: 'ok' }`).

Registering again with an address that's still pending replaces its password and sends a fresh
code — earlier codes stop working.

## Login (cookie-based)

```js
async function login(email, password) {
  const res = await fetch(`${BASE}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
    credentials: 'include', // keep the access_token/refresh_token cookies
  });
  if (!res.ok) throw await res.json(); // 401 INVALID_CREDENTIALS (also while the account is locked)
  const body = await res.json();
  if (body.mfaRequired) {
    // See mfa-totp-setup-and-verify.md — complete via POST /auth/mfa/verify
    // with { mfaChallengeToken: body.mfaChallengeToken, code }.
    return { mfaRequired: true, mfaChallengeToken: body.mfaChallengeToken };
  }
  return body; // { accessToken, accessTokenExpiresAt, refreshToken, refreshTokenExpiresAt, userId }
}
```

`loginHandler` sets `access_token`/`refresh_token` as `httpOnly` cookies (see
[Password & Email Auth](../api/password-email-auth.md)) — a browser client typically only needs
`credentials: 'include'` and never touches the token strings directly. For a browser-only app, set
`cookies.refreshTokenInBody: false` on the server: `refreshToken` is then left out of the JSON
body, so page script can never read it. A non-browser client (a mobile app, a service) reads the
JSON body's `accessToken`/`refreshToken` instead (keep `refreshTokenInBody` at its default `true`)
and sends the access token as `Authorization: Bearer <token>` on subsequent calls.

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
  const res = await fetch(`${BASE}/refresh`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    // Non-browser clients send the token; browser clients send {} and rely on the cookie.
    body: JSON.stringify(refreshToken ? { refreshToken } : {}),
    credentials: 'include',
  });
  if (!res.ok) throw await res.json(); // 401 INVALID_REFRESH_TOKEN → log in again
  return res.json(); // a NEW accessToken (+ refreshToken unless refreshTokenInBody: false)
}
```

Every refresh **rotates** the refresh token — the old one stops working immediately (see
[Password & Email Auth](../api/password-email-auth.md#refresh--logout)). Store the new
`refreshToken` from the response and discard the old one. Don't retry a refresh with a stale
token: within 10 seconds of its rotation it's merely refused (two tabs refreshing at once), but
after that, presenting an already-rotated token is treated as theft and **revokes the whole
session** — every token from that login — so the user has to log in again.

Refreshing also doesn't keep a session alive forever: 90 days after the login
(`session.absoluteLifetimeSeconds`) `/refresh` answers 401 `INVALID_REFRESH_TOKEN` regardless.
Each refresh re-runs `resolveAuthContext`, so the new access token carries current claims.

## Logout

```js
async function logout(refreshToken) {
  const res = await fetch(`${BASE}/logout`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    // Browser clients can omit the token: the handler falls back to the
    // httpOnly refresh_token cookie (credentials: 'include' sends it).
    body: JSON.stringify(refreshToken ? { refreshToken } : {}),
    credentials: 'include',
  });
  return res.json(); // { status: 'ok' } — both cookies are cleared
}

// Revoke every session for this user (all devices) instead of just one:
async function logoutEverywhere(accessToken) {
  const res = await fetch(`${BASE}/logout/all`, {
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
