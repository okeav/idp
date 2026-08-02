---
title: "Register, Verify, Login, Refresh, Logout"
package: "@okeav/idp-core"
category: "example"
tags: ["auth", "password", "sessions", "express"]
description: "The full password-auth lifecycle against a running idp-core server, including the token-refresh rotation cycle."
---

# Register, Verify, Login, Refresh, Logout

The complete password-based session lifecycle, using `fetch` against a server built with
[buildRouter()](quickstart-express.md) mounted at `/auth`.

## Prerequisites

- A running idp-core server (see [Quickstart: Express Server](quickstart-express.md)).
- Node's built-in `fetch` (Node ≥ 18) with cookie handling, or run these as `curl` calls with
  `-c cookies.txt -b cookies.txt` to persist cookies across requests.

## Register + verify

```js
const BASE = 'http://localhost:3000/auth';

async function register(email, password) {
  const res = await fetch(`${BASE}/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  return res.json(); // always { status: 'ok' } — enumeration-safe, see password-email-auth.md
}

// The verification code is printed to the server console by the
// onVerificationEmailRequested hook in a real app you'd email it instead.
async function verifyEmail(email, code) {
  const res = await fetch(`${BASE}/register/verify-email`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, code }),
  });
  return res.json(); // { status: 'ok', userId, email }
}
```

## Login (cookie-based)

```js
async function login(email, password) {
  const res = await fetch(`${BASE}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
    credentials: 'include', // keep the access_token/refresh_token cookies
  });
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
`credentials: 'include'` and never touches the token strings directly. A non-browser client (a
mobile app, a service) reads the JSON body's `accessToken`/`refreshToken` instead and sends the
access token as `Authorization: Bearer <token>` on subsequent calls.

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

## Refresh

```js
async function refresh(refreshToken) {
  const res = await fetch(`${BASE}/refresh`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ refreshToken }), // or omit and rely on the cookie
    credentials: 'include',
  });
  return res.json(); // a NEW accessToken + refreshToken — the old refresh token is now revoked
}
```

Every refresh **rotates** the refresh token — the old one stops working immediately (see
[Password & Email Auth](../api/password-email-auth.md#refresh--logout)). Store the new
`refreshToken` from the response and discard the old one; don't retry a refresh call with a stale
token expecting it to still work.

## Logout

```js
async function logout(refreshToken) {
  const res = await fetch(`${BASE}/logout`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ refreshToken }),
    credentials: 'include',
  });
  return res.json(); // { status: 'ok' }
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
