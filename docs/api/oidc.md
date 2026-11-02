---
title: "OpenID Connect (OIDC)"
package: "@okeav/idp-core"
category: "api-reference"
tags: ["oidc", "userinfo", "logout", "id-token"]
description: "ID-token claims, userinfoHandler and endSessionHandler — the OIDC layer built on top of the OAuth2 authorization server. Discovery is covered separately."
---

# OpenID Connect (OIDC)

The OIDC layer on top of the [OAuth2 authorization server](oauth2-authorization-server.md):
ID tokens, UserInfo and RP-initiated logout. ID-token signing is covered in
[Tokens & Signing](tokens-rs256.md); the discovery document in
[JWKS & OIDC Discovery](jwks-oidc-discovery.md).

## ID tokens

Issued by the `authorization_code` grant when the granted scopes include `openid` (never on
refresh). `openid` must be in the client's `allowedScopes` like any other scope. Claims:

| Claim | When |
|---|---|
| `sub`, `aud` (= `client_id`), `azp` (= `client_id`), `iss`, `jti`, `iat`, `exp` | always |
| `nonce` | when the **`/oauth2/authorize`** request carried one (it is stored with the code; a `nonce` sent to the token endpoint is ignored) |
| `auth_time` | when the user's last real login time is known — taken from the `auth_time` of the first-party access token presented at `/oauth2/authorize` (which first-party refreshes carry forward unchanged; sessions from before 0.4.0 have none) |
| `email`, `email_verified` | `email` scope granted |
| `name`, `given_name`, `family_name`, `picture`, `locale`, `zoneinfo` | `profile` scope granted (each only if set on the user) |

Lifetime is the client's `idTokenTTL` if set, else `config.ttls.idToken`. `email_verified` is
derived as `status !== 'PENDING_VERIFICATION'`. Relying parties must check `nonce` against the
value they sent, and `iss` on the authorization response (RFC 9207) as well as in the token.

The exported `issueIdToken(user, audience, nonce?, { scopes?, authTime?, ttlSeconds? })` releases
`openid email profile` claims when `scopes` is omitted.

## `GET /userinfo` — `userinfoHandler`

Mounted as `authContextMiddleware({ accept: ['oauth2-user'] })` → `userinfoHandler`. It accepts
**only an OAuth2 access token issued to a client on behalf of a user**: a first-party token (from
`/login`), a `client_credentials` token, or a missing/invalid/expired/revoked token is refused by
the middleware (`AUTH_REQUIRED` / `INVALID_TOKEN` / `TOKEN_REVOKED`, 401) before the handler runs.
An `Authorization: Bearer` header wins over the first-party session cookie (since 0.4.0), so the
RP's Bearer token is used even if the browser also sends a cookie; still, calling `/userinfo`
server-side is the usual pattern.

The handler then applies its own checks, answering in the OAuth 2.0 Bearer Token error format
(RFC 6750) rather than via `IdpError`:

- Without `openid` in the token's granted scopes →
  ```
  403
  WWW-Authenticate: Bearer error="insufficient_scope", scope="openid"
  { "error": "insufficient_scope", "error_description": "The openid scope is required" }
  ```
- The user no longer exists or isn't `ACTIVE` (suspended, administratively locked, deleted, pending verification… — a failed-password lockout doesn't count) →
  ```
  401
  WWW-Authenticate: Bearer error="invalid_token"
  { "error": "invalid_token", "error_description": "User not found" }
  ```
  (The same 401 shape with `"The access token is missing or invalid"` is returned if you mount
  `userinfoHandler` yourself behind no auth middleware.)

Unexpected errors go to `next(err)`. Successful responses carry `Cache-Control: no-store`.

Claims are released **per granted scope only** (OIDC Core §5.4), read from `req.auth.scopes`:

- Always: `sub`.
- `email` scope: `email`, `email_verified`.
  > `email_verified` is derived as `status !== 'PENDING_VERIFICATION'`. Since inactive users are
  > refused outright, in practice it is `true` for every user `/userinfo` answers for.
- `profile` scope: `name` (falls back through `displayName` → `"firstName lastName"`.trim() →
  omitted), `given_name`, `family_name`, `picture` (from `avatarUrl`, which must be `https`),
  `locale`, `zoneinfo`, `updated_at` (Unix seconds).

Undefined fields are stripped before the response — absent profile data simply doesn't appear in
the JSON (never sent as `null`).

## `GET /oidc/end-session` — `endSessionHandler`

RP-initiated logout (OIDC RP-Initiated Logout 1.0). Mounted behind `authContextMiddleware({
optional: true })` — works with or without the browser's first-party session cookie.

Query: `id_token_hint?, post_logout_redirect_uri?, state?`.

Because this is a plain GET any site can trigger, what it ends is deliberately narrow — **it never
signs the user out of every device** (that's `POST /logout/all`):

1. **`id_token_hint`**, if present, must be an **ID token** this IdP issued — an access token or
   MFA-challenge token is refused. Its signature and issuer are verified, but an **expired hint is
   accepted**, as the spec recommends. Invalid → `INVALID_REQUEST` (400, `'Invalid
   id_token_hint'`). If the request also carries a first-party session for a different user →
   `INVALID_REQUEST` (400).
2. **If `post_logout_redirect_uri` is supplied, `id_token_hint` is mandatory** — the hint's `aud`
   says which client's allowlist to check → `INVALID_REQUEST` (400, `'id_token_hint is required
   when post_logout_redirect_uri is supplied'`). That client must exist and be `ACTIVE`
   (`OAUTH_CLIENT_NOT_FOUND`, 400), and the URI must be in its `postLogoutRedirectUris` — **falling
   back to its regular `redirectUris`** when no dedicated post-logout list is set
   (`INVALID_REDIRECT_URI`, 400 otherwise).
3. **The browser's own IdP session** — if a first-party session came with the request, that one
   session is revoked and the session cookies are cleared.
4. **The hinted client's sessions for that user** — only when a valid hint comes **together with
   that same user's first-party session** (normally the browser's cookie): every session issued to the hint's
   client (`aud`) for the hint's `sub` is then revoked (`SessionRepository.revokeForClient`). A
   hint alone ends nothing (0.4.0) — ID tokens travel through URLs and logs, and whoever holds one
   must not be able to sign its user out of the relying party. The user's other clients and
   devices are untouched.
5. Revoked sessions' access tokens are marked revoked in the cache as well; with
   `session.verifyOnEachRequest` (default — see [Middleware](middleware.md)) they stop working on
   every instance at the next request.
6. Fires `auditLog('END_SESSION', { userId, clientId, revokedSessions })` when a user was
   identified.
7. Redirects to `post_logout_redirect_uri?state=...` if supplied; otherwise `200 { status: 'ok' }`.

A call without a session is a no-op `200` (apart from the redirect, when a valid hint and URI are
given). There is **no confirmation step**: a page that triggers this GET in the user's browser ends
that browser's IdP session (and, with a hint, that client's sessions for the user) — narrow by
design, as above. Error and rejection logs record the path only — never the query string, which
carries the `id_token_hint`.

## Related

- [JWKS & OIDC Discovery](jwks-oidc-discovery.md) — the `/.well-known/openid-configuration`
  document pointing at these endpoints.
- [OAuth2 Authorization Server](oauth2-authorization-server.md) — `nonce`, PKCE, consent, token
  kinds.
- [Tokens & Signing (RS256)](tokens-rs256.md) — `issueIdToken`, `verifyIssuedToken`.
