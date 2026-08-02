---
title: "OpenID Connect (OIDC)"
package: "@okeav/idp-core"
category: "api-reference"
tags: ["oidc", "userinfo", "logout"]
description: "userinfoHandler and endSessionHandler — the OIDC layer built on top of the OAuth2 authorization server. Discovery is covered separately."
---

# OpenID Connect (OIDC)

The OIDC layer on top of the [OAuth2 authorization server](oauth2-authorization-server.md):
UserInfo and RP-initiated logout. ID-token issuance is covered in
[Tokens & Signing](tokens-rs256.md); the discovery document in
[JWKS & OIDC Discovery](jwks-oidc-discovery.md).

## `GET /userinfo` — `userinfoHandler`

Requires an authenticated caller. The handler itself has its own `!req.auth?.userId` guard that
writes the OAuth 2.0 Bearer Token error format directly (RFC 6750) instead of using the
`IdpError`/`next(err)` pattern every other handler uses:

```
401
WWW-Authenticate: Bearer error="invalid_token"
{ "error": "invalid_token", "error_description": "The access token is missing or invalid" }
```

**In practice, through `buildRouter()`, that specific branch is unreachable.** The route is mounted
as `router.get('/userinfo', authContextMiddleware(), userinfoHandler)` — `authContextMiddleware()`
is called *without* `{ optional: true }`, so a missing/invalid/expired token is already rejected by
the middleware itself (the standard `IdpError` → `next(err)` path) before `userinfoHandler` ever
runs. The handler's own RFC 6750 branch only matters if you mount `userinfoHandler` yourself behind
different (or no) auth middleware.

The one branch that *is* reachable via the default router: a **valid** token whose user was deleted
after the token was issued still hits the handler's second guard, giving the same RFC 6750 shape
with `error_description: "User not found"`. This handler is also not wrapped in try/catch with a
`next` fallback for unexpected exceptions — an unhandled storage error here would need to be caught
by generic Express error-handling middleware rather than surfacing as a structured `IdpError`.

Claims returned are gated by `req.auth.claims.scope` (space-delimited string set at token issuance
— see [OAuth2](oauth2-authorization-server.md#token-endpoint--post-oauth2token)):

- Always: `sub`.
- Scope includes `email` **or** `openid`: `email`, `email_verified`.
  > `email_verified` is derived as `status !== 'PENDING_VERIFICATION'` — **any** status other than
  > pending-verification (including `SUSPENDED`, `LOCKED`, `DISABLED`) reads as `true`. This
  > conflates "verified" with "not currently pending verification," not a true independently-
  > tracked verification flag.
- Scope includes `profile`: `name` (falls back through `displayName` → `"firstName
  lastName"`.trim() → omitted), `given_name`, `family_name`, `picture` (from `avatarUrl`),
  `locale`, `zoneinfo`, `updated_at` (Unix seconds).

Undefined fields are stripped before the response — absent profile data simply doesn't appear in
the JSON (never sent as `null`).

## `GET /oidc/end-session` — `endSessionHandler`

RP-initiated logout. `authContextMiddleware({ optional: true })` — works with or without a
session cookie, since a client-side logout may present only an `id_token_hint`.

Query: `post_logout_redirect_uri?, state?, id_token_hint?`.

1. `userId = req.auth?.userId || null`.
2. If `id_token_hint` present, verifies it via `verifyIssuedToken` (returns `null` rather than
   throwing on failure) — invalid hint → `INVALID_REQUEST` (400, `'Invalid id_token_hint'`).
   `userId = userId || hintClaims.sub` (an active session takes precedence over the hint's `sub`
   if both are present).
3. **If `post_logout_redirect_uri` is supplied, `id_token_hint` becomes mandatory** — the handler
   needs the hint's `aud` claim to know which client's redirect-URI allowlist to check, even if
   the caller is already authenticated via cookie. No hint (or no `aud`) →
   `INVALID_REQUEST` (400, `'id_token_hint is required when post_logout_redirect_uri is supplied'`).
   The client (`hintClaims.aud`) must exist and be `ACTIVE` → `OAUTH_CLIENT_NOT_FOUND` (400)
   otherwise. `post_logout_redirect_uri` is validated against `client.postLogoutRedirectUris` if
   configured, **falling back to the client's regular `redirectUris` list** if no dedicated
   post-logout list is set → `INVALID_REDIRECT_URI` (400) otherwise.
4. If a `userId` was resolved (from session or hint), calls `sessionRepository.revokeAllForUser` —
   **this is a global logout, revoking every session for the user, not just the one tied to the
   presented `id_token_hint`'s client.** Fires `auditLog('END_SESSION', { userId, revokedSessions })`.
5. Redirects to `post_logout_redirect_uri?state=...` if supplied; otherwise `200 { status: 'ok' }`.

**No cookies are read or cleared by this handler** — it's purely token/session-store based. If
your app stores tokens in cookies, clearing them client-side (or via your own `/logout` call —
see [Password & Email Auth](password-email-auth.md)) is a separate step.

## Related

- [JWKS & OIDC Discovery](jwks-oidc-discovery.md) — the `/.well-known/openid-configuration`
  document pointing at these endpoints.
- [OAuth2 Authorization Server](oauth2-authorization-server.md)
- [Tokens & Signing (RS256)](tokens-rs256.md) — `issueIdToken`, `verifyIssuedToken`.
