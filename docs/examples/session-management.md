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

## List active sessions

```js
const BASE = 'http://localhost:3000/auth';
const authHeader = (token) => ({ Authorization: `Bearer ${token}` });

async function listSessions(accessToken) {
  const res = await fetch(`${BASE}/me/sessions`, { headers: authHeader(accessToken) });
  return res.json();
  // [{ id, ipAddress, deviceInfo, createdAt, expiresAt }, ...]
  // Note: deviceInfo is the raw User-Agent string captured at login/refresh time —
  // render it through your own UA-parsing library if you want a friendlier
  // "Chrome on Windows" label; idp-core doesn't format it for display.
}
```

## Revoke one session (e.g. "sign out this device")

```js
async function revokeSession(accessToken, sessionId) {
  const res = await fetch(`${BASE}/me/sessions/${sessionId}`, {
    method: 'DELETE',
    headers: authHeader(accessToken),
  });
  if (!res.ok) throw await res.json(); // REFRESH_TOKEN_NOT_FOUND if not found or not yours
  return res.json(); // { status: 'ok' }
}
```

Revoking a specific session by ID immediately invalidates that session's access token too (not
just the refresh token) — the revoked device is signed out right away, not just unable to refresh.

## Sign out everywhere

Two endpoints do overlapping things here — pick based on whether you need the revoked count:

```js
// Returns how many sessions were revoked, but does NOT proactively invalidate
// their still-live access tokens (those expire naturally, same caveat as
// password change/reset — see password-email-auth.md).
async function revokeAllSessions(accessToken) {
  const res = await fetch(`${BASE}/me/sessions`, { method: 'DELETE', headers: authHeader(accessToken) });
  return res.json(); // { status: 'ok', revokedCount: 3 }
}

// Functionally similar, but doesn't report a count and is what you'd wire to
// a plain "Log out everywhere" button that doesn't need the number.
async function logoutEverywhere(accessToken) {
  const res = await fetch(`${BASE}/logout/all`, { method: 'POST', headers: authHeader(accessToken) });
  return res.json(); // { status: 'ok' }
}
```

## Putting it together (a settings page)

```js
async function renderSessionsPage(accessToken) {
  const sessions = await listSessions(accessToken);
  return sessions.map((s) => ({
    id: s.id,
    label: `${s.deviceInfo || 'Unknown device'} — ${s.ipAddress}`,
    loggedInAt: s.createdAt,
    onRevoke: () => revokeSession(accessToken, s.id),
  }));
}
```

## Related

- [Password & Email Auth](../api/password-email-auth.md) — full self-service handler reference.
- [Repository Adapters](../api/repository-adapters.md) — `SessionRepository`, if you need to build
  your own session-listing query beyond what `listActiveForUser` exposes.
- [Register, Login, Refresh, Logout example](register-login-refresh-logout.md)
