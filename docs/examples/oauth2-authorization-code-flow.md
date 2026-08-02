---
title: "OAuth2 Authorization Code Flow (with PKCE)"
package: "@okeav/idp-core"
category: "example"
tags: ["oauth2", "pkce", "authorization-server"]
description: "Register a client, run the full authorize -> consent -> token exchange, then use and refresh the resulting access token."
---

# OAuth2 Authorization Code Flow (with PKCE)

Using idp-core as a standalone OAuth2 authorization server for a relying-party application. See
[OAuth2 Authorization Server](../api/oauth2-authorization-server.md) for the full endpoint
reference.

## Prerequisites

- A running idp-core server with the full router mounted (`buildRouter()` includes the OAuth2
  routes by default).
- **Register and approve a client first** — new clients start `PENDING_APPROVAL` and can't
  complete an authorize/token exchange until approved. In this example, approval is done directly
  against the unauthenticated `/oauth2/clients/:id/approve` route for simplicity — in production,
  gate client-management routes behind your own admin auth (see
  [Router & Schemas](../api/router-and-schemas.md)).

## 1. Register a client

```js
const BASE = 'http://localhost:3000/auth';

const registerRes = await fetch(`${BASE}/oauth2/clients`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    name: 'My Relying App',
    slug: 'my-relying-app',
    clientType: 'public', // no client_secret needed — this app can't keep one confidential
    redirectUris: ['https://app.example.com/callback'],
    allowedScopes: ['openid', 'email', 'profile'],
    allowedGrants: ['authorization_code', 'refresh_token'],
  }),
});
const { clientId, status } = await registerRes.json(); // status: 'PENDING_APPROVAL'

// An operator approves it (e.g. via an internal admin tool):
await fetch(`${BASE}/oauth2/clients/${clientId}/approve`, { method: 'POST' });
```

## 2. Generate a PKCE pair (public client)

```js
import crypto from 'crypto';

const codeVerifier = crypto.randomBytes(32).toString('base64url');
const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
```

## 3. Redirect the user to `/oauth2/authorize`

```js
const authorizeUrl = new URL(`${BASE}/oauth2/authorize`);
authorizeUrl.search = new URLSearchParams({
  client_id: clientId,
  redirect_uri: 'https://app.example.com/callback',
  response_type: 'code',
  scope: 'openid email profile',
  state: crypto.randomBytes(16).toString('hex'), // your own CSRF token, echoed back
  code_challenge: codeChallenge,
  code_challenge_method: 'S256',
}).toString();

// window.location = authorizeUrl.toString();
```

If the browser isn't authenticated (no valid `access_token` cookie), the endpoint responds
`401 { action: 'login_required', ... }` instead of proceeding — redirect to your own login UI and
retry this same authorize URL after login. If the user hasn't consented to these scopes yet, it
responds `200 { action: 'consent_required', client, scopes, missingScopes, ... }` — show a consent
screen and POST the same params to `/oauth2/authorize/confirm` to proceed, or
`/oauth2/authorize/deny` to reject.

Once authenticated **and** consented, the endpoint redirects directly to
`https://app.example.com/callback?code=...&state=...`.

## 4. Exchange the code for tokens

Your callback route (`https://app.example.com/callback`) extracts `code`/`state`, verifies `state`
matches what you generated, then exchanges the code server-side (never in the browser, to keep
`code_verifier` off the client for a confidential setup — for a public client like this one it's
fine client-side too, since there's no secret to protect):

```js
const tokenRes = await fetch(`${BASE}/oauth2/token`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    grant_type: 'authorization_code',
    code,
    redirect_uri: 'https://app.example.com/callback', // must match exactly
    client_id: clientId,
    code_verifier: codeVerifier,
  }),
});
const tokens = await tokenRes.json();
// { access_token, refresh_token, id_token, token_type: 'Bearer', expires_in, scope }
```

## 5. Use the access token

```js
const userinfoRes = await fetch(`${BASE}/userinfo`, {
  headers: { Authorization: `Bearer ${tokens.access_token}` },
});
const profile = await userinfoRes.json(); // fields gated by `scope` — see oidc.md
```

## 6. Refresh

```js
const refreshRes = await fetch(`${BASE}/oauth2/token`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ grant_type: 'refresh_token', refresh_token: tokens.refresh_token, client_id: clientId }),
});
// Note: no id_token on refresh. Scope is the originally-consented scope from
// step 4, narrowed against the client's CURRENT allowedScopes — it can only
// hold steady or shrink on refresh, never widen. See
// oauth2-authorization-server.md's refresh_token grant section for detail.
```

## Related

- [OAuth2 Authorization Server](../api/oauth2-authorization-server.md) — full endpoint reference,
  including the client-credentials grant and revocation/introspection.
- [OIDC](../api/oidc.md) — `/userinfo` scope-gated claims, RP-initiated logout.
- [Errors](../api/errors.md)
