---
title: "List and Revoke Sessions"
package: "@okeav/idp-core"
category: "example"
tags: ["auth", "sessions"]
description: "Build a 'devices logged in' settings page: list active sessions, revoke one, revoke all, or sign out everywhere."
---

# List and Revoke Sessions

A typical "devices logged in" account-settings page, using the self-service session endpoints. See
[Password & Email Auth](../api/password-email-auth.md#self-service-identity-me) for the full
handler reference.

## Prerequisites

- A logged-in user (see [Register, Login, Refresh, Logout](register-login-refresh-logout.md)).
- If your settings page calls these endpoints with the session **cookie** from a different origin
  than the IdP, list that origin in `cookies.trustedOrigins` — cookie-authenticated `DELETE`/`POST`
  requests from other origins get 403 `CSRF_ORIGIN_REJECTED`. The examples below use a Bearer
  token, which isn't subject to that check.

## What a "session" is

Each row returned here is one live refresh token. A login creates one; every refresh **replaces**
it with a new row (same login, new `id`, new `createdAt`) and revokes the old one. So `createdAt`
is when the session was last refreshed, not when the user logged in, and a session's `id` changes
each time it refreshes. Every session ends at the latest 90 days after its login
(`session.absoluteLifetimeSeconds`), however actively it's used.

The list includes sessions held by OAuth2 apps the user authorized (their refresh tokens are rows
too) alongside the user's own logins; the response doesn't tell them apart. To manage app access
specifically, use the consent endpoints (`GET /oauth2/consent/sessions`,
`DELETE /oauth2/consent/sessions/:clientId` — see
[OAuth2 Authorization Server](../api/oauth2-authorization-server.md)), which also revoke that
app's tokens.

## List active sessions

```js
const BASE = 'http://localhost:3000/auth';
const authHeader = (token) => ({ Authorization: `Bearer ${token}` });

async function listSessions(accessToken) {
  const res = await fetch(`${BASE}/me/sessions`, { headers: authHeader(accessToken) });
  return res.json();
  // [{ id, ipAddress, deviceInfo, createdAt, expiresAt }, ...] — newest first
  // Note: deviceInfo is the raw User-Agent string captured at login/refresh time —
  // render it through your own UA-parsing library if you want a friendlier
  // "Chrome on Windows" label; idp-core doesn't format it for display.
}
```

## Revoke one session (e.g. "sign out this device")

```js
async function revokeSession(accessToken, sessionId) {
  const res = await fetch(`${BASE}/me/sessions/${encodeURIComponent(sessionId)}`, {
    method: 'DELETE',
    headers: authHeader(accessToken),
  });
  if (!res.ok) throw await res.json(); // 404 REFRESH_TOKEN_NOT_FOUND if not found, not yours, or already refreshed
  return res.json(); // { status: 'ok' }
}
```

Revoking a specific session by ID immediately invalidates that session's access token too (not
just the refresh token) — the revoked device is signed out right away, not just unable to refresh.
Because a session's `id` changes on every refresh, re-fetch the list if a revoke answers 404.

## Sign out everywhere

Two endpoints do overlapping things here — pick based on whether you need the revoked count.
Both revoke **every** session, the caller's own included (and any OAuth2 app sessions). With
`session.verifyOnEachRequest` on (the default) their access tokens — including the one making this
call — stop working on the next request, on every instance; with it off, they stay valid until
they expire (see [Middleware](../api/middleware.md)). A refresh racing with either call can't
resurrect a session: it re-checks the user's revoke-all time after rotating. The same goes for a
login that was still checking its password when the call landed (it answers 401 `TOKEN_REVOKED`).
Likewise an OAuth2 authorization code issued before the call but not yet redeemed is refused
(`INVALID_GRANT`) at `/oauth2/token` — as is any code whose authorizing session has been revoked —
so it can't become a new session afterwards.

```js
// Returns how many sessions were revoked.
async function revokeAllSessions(accessToken) {
  const res = await fetch(`${BASE}/me/sessions`, { method: 'DELETE', headers: authHeader(accessToken) });
  return res.json(); // { status: 'ok', revokedCount: 3 }
}

// Functionally similar, but doesn't report a count and is what you'd wire to
// a plain "Log out everywhere" button that doesn't need the number.
async function logoutEverywhere(accessToken) {
  const res = await fetch(`${BASE}/session/logout/all`, { method: 'POST', headers: authHeader(accessToken) });
  return res.json(); // { status: 'ok' }
}
```

Signing out everywhere doesn't remove **passkeys**: a passkey is a login method of its own. List
and delete them with `GET /me/passkeys` and `DELETE /me/passkeys/:credentialId` (the delete needs a
recent login — 401 `REAUTHENTICATION_REQUIRED` otherwise; see [WebAuthn](../api/webauthn.md)).

## Putting it together (a settings page)

```js
async function renderSessionsPage(accessToken) {
  const sessions = await listSessions(accessToken);
  return sessions.map((s) => ({
    id: s.id,
    label: `${s.deviceInfo || 'Unknown device'} — ${s.ipAddress}`,
    lastActiveAt: s.createdAt, // the last refresh (or the login, if never refreshed)
    onRevoke: () => revokeSession(accessToken, s.id),
  }));
}
```

## Related

- [Password & Email Auth](../api/password-email-auth.md) — full self-service handler reference.
- [Repository Adapters](../api/repository-adapters.md) — `SessionRepository`, if you need to build
  your own session-listing query beyond what `listActiveForUser` exposes (rows carry `kind`,
  `familyId` and `authTime`).
- [Register, Login, Refresh, Logout example](register-login-refresh-logout.md)
