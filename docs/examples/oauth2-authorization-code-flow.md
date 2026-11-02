---
title: "OAuth2 Authorization Code Flow (with PKCE)"
package: "@okeav/idp-core"
category: "example"
tags: ["oauth2", "pkce", "authorization-server"]
description: "Register a client, run the full authorize -> consent -> token exchange with PKCE (S256) and an OIDC nonce, then use and refresh the resulting access token."
---

# OAuth2 Authorization Code Flow (with PKCE)

Using idp-core as a standalone OAuth2 authorization server for a relying-party application. See
[OAuth2 Authorization Server](../api/oauth2-authorization-server.md) for the full endpoint
reference.

## Prerequisites

- A running idp-core server with the router mounted. `buildRouter()` includes the OAuth2
  authorize/token/consent routes by default, but the `/oauth2/clients*` management routes **only**
  when you pass `clientManagement` with your own admin middleware (see
  [Router & Schemas](../api/router-and-schemas.md)).
- **Register and approve a client first** — new clients start `PENDING_APPROVAL` and can't
  complete an authorize/token exchange until approved.
- Your consent page runs on the IdP's origin, or on an origin listed in
  `cookies.trustedOrigins` — `POST /oauth2/authorize/confirm` and `/deny` are cookie-authenticated
  and refuse other origins (403 `CSRF_ORIGIN_REJECTED`).

Server side, for this example — admin auth is yours to define; here, any caller whose access
token carries an `admin` role claim (set by your `resolveAuthContext`):

```js
import express from 'express';
import { buildRouter, authContextMiddleware, cookieParser, idpErrorHandler } from '@okeav/idp-core';

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false })); // form-encoded token requests (the OAuth2 norm)
app.use(cookieParser());

const requireAdmin = [
  authContextMiddleware(),
  (req, res, next) => (req.auth.claims.role === 'admin'
    ? next()
    : res.status(403).json({ error: 'FORBIDDEN' })),
];

app.use('/auth', buildRouter({ clientManagement: { middleware: requireAdmin } }));
app.use(idpErrorHandler()); // { error, message } for client errors; no internals on 500s
```

## 1. Register a client

```js
const BASE = 'https://idp.example.com/auth';
const adminHeaders = { Authorization: `Bearer ${adminAccessToken}` }; // an admin's access token

const registerRes = await fetch(`${BASE}/oauth2/clients`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', ...adminHeaders },
  body: JSON.stringify({
    name: 'My Relying App',
    slug: 'my-relying-app',
    clientType: 'public', // no client_secret — this app can't keep one confidential
    redirectUris: ['https://app.example.com/callback'], // https (http only for loopback)
    allowedScopes: ['openid', 'email', 'profile'],       // openid must be listed explicitly
    allowedGrants: ['authorization_code', 'refresh_token'],
  }),
});
const { clientId, status } = await registerRes.json(); // status: 'PENDING_APPROVAL'

// An operator approves it (e.g. via an internal admin tool):
await fetch(`${BASE}/oauth2/clients/${clientId}/approve`, { method: 'POST', headers: adminHeaders });
```

For a confidential client (a server-side app), omit `clientType` and keep the `clientSecret` from
the registration response — it is never shown again (only replaced by rotate-secret).

## 2. Generate a PKCE pair, `state` and `nonce`

PKCE with `S256` is required for public clients and, by default (`oauth2.requirePkce: 'all'`),
for confidential clients too. `plain` is refused.

```js
import crypto from 'crypto';

const codeVerifier = crypto.randomBytes(32).toString('base64url'); // 43 chars
const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
const oauthState = crypto.randomBytes(16).toString('hex'); // your own CSRF token, echoed back
const nonce = crypto.randomBytes(16).toString('hex');      // echoed into the ID token

// Keep codeVerifier, oauthState and nonce with the user's pending login (e.g. your own session).
```

## 3. Send the user to `/oauth2/authorize`

```js
const authorizeUrl = new URL(`${BASE}/oauth2/authorize`);
authorizeUrl.search = new URLSearchParams({
  client_id: clientId,
  redirect_uri: 'https://app.example.com/callback',
  response_type: 'code',
  scope: 'openid email profile',
  state: oauthState,
  nonce,
  code_challenge: codeChallenge,
  code_challenge_method: 'S256', // required with a code_challenge
}).toString();
```

`GET /oauth2/authorize` answers JSON (or a redirect), so the IdP's own frontend calls it with the
user's session and acts on the result:

- `401 { action: 'login_required', reason }` — not logged in at the IdP (`reason:
  'unauthenticated'`), or the login is too old for the request's `prompt=login` / `max_age`
  (`'prompt_login'` / `'max_age'`): show your login UI, then retry the same URL (a login within the
  last 60 seconds satisfies `prompt=login` and `max_age=0`).
- `200 { action: 'consent_required', consent_challenge, client, scopes, missingScopes }` — show a
  consent screen (step 3a).
- `302` to `https://app.example.com/callback?code=...&state=...&iss=...` — the user already
  consented to these scopes.

The client can add `prompt` (`none`, `login`, `consent`, `select_account`) and `max_age` to the
authorize URL. With `prompt=none` there is never a login or consent screen: instead of
`login_required` / `consent_required` the IdP redirects to the callback with
`error=login_required` or `error=consent_required` (plus `state` and `iss`). `prompt=consent`
always shows the consent screen. See
[OAuth2 Authorization Server](../api/oauth2-authorization-server.md#prompt-and-max_age).

### 3a. The consent page

The consent page posts **only** the `consent_challenge` it received — the server stored the
validated request (client, scopes, redirect URI, state, nonce, PKCE challenge) and acts on exactly
that. The challenge is single-use, bound to this user, and expires after `ttls.authCode` (10
minutes by default).

```js
// Running on the IdP's origin (or a cookies.trustedOrigins origin), with the user's session cookie.
const res = await fetch(authorizeUrl, { credentials: 'include' }); // follows a 302 if already consented
const body = res.redirected ? null : await res.json();

if (body?.action === 'login_required') {
  // send the user to your login page (even if signed in — body.reason may be 'prompt_login' or
  // 'max_age'), then come back to this URL
} else if (body?.action === 'consent_required') {
  // render body.client.name, body.missingScopes … and a form carrying only the challenge:
  renderConsent(body);
}
```

```html
<!-- The response to either button is a 302 to the client's redirect_uri, which the browser
     follows as a normal navigation. Form posts need express.urlencoded() mounted, as above. -->
<form method="post">
  <input type="hidden" name="consent_challenge" value="<consent_challenge from the response>">
  <button formaction="/auth/oauth2/authorize/confirm">Allow</button>
  <button formaction="/auth/oauth2/authorize/deny">Deny</button>
</form>
```

(A `fetch()` POST with `{ consent_challenge }` as JSON works too, but `fetch` can't follow a
cross-origin redirect to the client for you — navigate the browser instead.)

A deny redirects to `redirect_uri?error=access_denied&error_description=...&state=...&iss=...`.
An unknown, expired or reused challenge is `400 INVALID_CONSENT_CHALLENGE` — restart from the
authorize URL.

## 4. Exchange the code for tokens

Your callback route (`https://app.example.com/callback`) checks that `state` matches what you
generated and that `iss` equals the IdP's issuer, then exchanges the code. The code is single-use:
presenting it a second time revokes everything the first exchange issued.

```js
const tokenRes = await fetch(`${BASE}/oauth2/token`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: 'https://app.example.com/callback', // must match exactly
    client_id: clientId, // public client: client_id alone authenticates it
    code_verifier: codeVerifier,
  }),
});
const tokens = await tokenRes.json();
// { access_token, refresh_token, id_token, token_type: 'Bearer', expires_in, scope }
// On failure: 400 { error: 'INVALID_GRANT', message } (bad/used code, redirect_uri or PKCE
// mismatch, or the user signed out everywhere / withdrew or re-granted consent since the code was
// issued), 401 { error: 'INVALID_CLIENT', ... }, etc.
```

A **confidential** client authenticates with HTTP Basic (`client_secret_basic`) — or with
`client_id` + `client_secret` in the body, but never both:

```js
const basic = Buffer.from(
  `${encodeURIComponent(clientId)}:${encodeURIComponent(clientSecret)}`,
).toString('base64');

const tokenRes = await fetch(`${BASE}/oauth2/token`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded', Authorization: `Basic ${basic}` },
  body: new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri, code_verifier: codeVerifier }),
});
```

Then validate the ID token: signature against the IdP's JWKS, `iss`, `aud` (= your `client_id`),
`exp`, and **`nonce` equal to the one you generated in step 2**. Its email/profile claims follow
the granted scopes.

## 5. Use the access token

```js
const userinfoRes = await fetch(`${BASE}/userinfo`, {
  headers: { Authorization: `Bearer ${tokens.access_token}` },
});
const profile = await userinfoRes.json(); // claims gated by the granted scopes — see oidc.md
```

The access token is an `oauth2-user` token (`aud` = your `client_id`). It is **not** accepted by
the IdP's first-party routes (`/me`, `/password/change`, …). Your own API accepts it by opting in
and checking scopes:

```js
app.get('/api/profile',
  authContextMiddleware({ accept: ['oauth2-user'] }),
  (req, res) => {
    if (!req.auth.scopes.includes('profile')) return res.status(403).json({ error: 'INSUFFICIENT_SCOPE' });
    res.json({ userId: req.auth.userId, clientId: req.auth.clientId });
  },
);
```

## 6. Refresh

```js
const refreshRes = await fetch(`${BASE}/oauth2/token`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: tokens.refresh_token, client_id: clientId }),
});
const rotated = await refreshRes.json(); // store rotated.refresh_token — the old one is now spent
// Notes:
// - no id_token on refresh;
// - scope is the originally consented scope narrowed against the client's CURRENT
//   allowedScopes — it can only hold steady or shrink, never widen;
// - the refresh token only works for the client it was issued to (presented by another client,
//   it is revoked); a refused refresh (e.g. the user was suspended) doesn't spend it;
// - replaying a spent refresh token (after a 10 s grace) revokes the whole token family;
// - the family ends session.absoluteLifetimeSeconds (90 days) after the code exchange.
```

## 7. Revoke on logout

```js
await fetch(`${BASE}/oauth2/token/revoke`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({ token: rotated.refresh_token, client_id: clientId }), // client auth required
}); // always 200 { status: 'ok' }
```

## Related

- [OAuth2 Authorization Server](../api/oauth2-authorization-server.md) — full endpoint reference,
  including the client-credentials grant and revocation/introspection.
- [OIDC](../api/oidc.md) — ID-token claims, `/userinfo` scope-gated claims, RP-initiated logout.
- [Errors](../api/errors.md)
