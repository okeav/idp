---
title: "OAuth2 Authorization Server"
package: "@okeav/idp-core"
category: "api-reference"
tags: ["oauth2", "authorization-server", "pkce"]
description: "Authorization code + PKCE, client credentials, refresh token grants; client registration/lifecycle; consent; token revocation and introspection."
---

# OAuth2 Authorization Server

A full OAuth2 authorization-server surface: authorization-code grant (with optional PKCE),
client-credentials grant, refresh-token grant, client registration/lifecycle, consent management,
and RFC 7009/7662 revocation/introspection. See [OIDC](oidc.md) for the ID-token/UserInfo/discovery
layer built on top of this, and [Tokens & Signing](tokens-rs256.md) for how tokens are signed.

## Grant support matrix

| Grant | Client type | Refresh token issued | ID token issued |
|---|---|---|---|
| `authorization_code` | confidential or public (PKCE) | yes | yes, if `scope` includes `openid` |
| `refresh_token` | confidential or public | yes (rotated) | **no**, even if the original grant included `openid` |
| `client_credentials` | confidential only | no (per RFC 6749 §4.4) | no |

A client's own `allowedGrants` array is authoritative per-request — a client must be explicitly
provisioned with a grant even if the server supports it in principle
(`assertGrantAllowed(client, grantType)` → `INVALID_REQUEST` 400 if not listed).

## Authorization endpoint

**`GET /oauth2/authorize`** — query: `client_id, redirect_uri, response_type, scope?, state?,
code_challenge?, code_challenge_method?` (`authorizeQuerySchema`). `authContextMiddleware({
optional: true })` — behaves differently for logged-in vs. anonymous callers rather than requiring
auth outright.

Three outcomes, no cookies ever set by this handler:

1. **Not authenticated** → `401 { action: 'login_required', client_id, redirect_uri, scope, state, code_challenge, code_challenge_method, response_type }` — your frontend redirects to your own login UI and replays this request after auth.
2. **Missing consent** → `200 { action: 'consent_required', client: { name, logoUrl, websiteUrl, privacyPolicyUrl }, scopes, missingScopes, ...same echo fields }`.
3. **Already consented** → issues an authorization code and `302`-redirects to `redirect_uri?code=...&state=...`.

Scope defaults to `'openid'` if omitted. `openid` is always implicitly allowed regardless of the
client's `allowedScopes`; every other requested scope must be in `client.allowedScopes` or the
request fails `INVALID_REQUEST` (400). Consent is scope-set-based (`missingScopes = requested -
previously-consented`) — there's no separate "skip consent for first-party clients" flag; the only
bypass is a prior matching consent record via `POST /oauth2/authorize/confirm`.

Errors: `INVALID_REQUEST` (400, `response_type !== 'code'`, or disallowed scopes);
`OAUTH_CLIENT_NOT_FOUND` (400, client missing or not `ACTIVE` — **also returned for a
`PENDING_APPROVAL` client**, since the check is just `status !== ACTIVE`, so the code alone can't
distinguish "doesn't exist" from "not approved yet"); `INVALID_REDIRECT_URI` (400, not in
`client.redirectUris`).

**`POST /oauth2/authorize/confirm`** (auth required) — body: `client_id, redirect_uri, scope?,
state?, code_challenge?, code_challenge_method?`. Upserts consent with **exactly the requested
scopes** (an upsert, not necessarily a union with prior consent — confirm against your storage
adapter's `ConsentRepository.upsert` semantics if that distinction matters for your app), then
issues a code and redirects — same redirect shape as outcome 3 above. No JSON success body.

**`POST /oauth2/authorize/deny`** — body: `redirect_uri, state?, client_id?` (`client_id` is
schema-optional but functionally required — see below). Validates `redirect_uri` against the named
client's registered `redirectUris` (same `loadActiveClient`/`validateRedirectUri` path as
`authorizeHandler`/`confirmConsentHandler`) before redirecting to
`redirect_uri?error=access_denied&error_description=...&state=...`.

> **`client_id` must resolve to a real, `ACTIVE` client even though the schema marks it
> optional.** Omitting it, or passing an unknown/inactive `client_id`, fails with
> `OAUTH_CLIENT_NOT_FOUND` (400) rather than redirecting — there is no path through this handler
> that skips client/redirect-URI validation. An unregistered `redirect_uri` fails with
> `INVALID_REDIRECT_URI` (400) instead of being followed.

## Token endpoint — `POST /oauth2/token`

Dispatches on `grant_type` (`tokenSchema`, `.passthrough()`). Unsupported `grant_type` →
`INVALID_REQUEST` (400).

### `authorization_code`

Body adds: `code, redirect_uri, client_id, client_secret?, code_verifier?, nonce?`. The code is
**atomically consumed** (single-use) via `consumeByCodeHash`; `client_id` and `redirect_uri` must
match exactly what was stored at authorize time.

**PKCE**: only enforced if the authorize-time request included a `code_challenge` — if it didn't,
`code_verifier` is never required, regardless of client type (PKCE is opt-in per-request here, not
mandated by `clientType: 'public'`). When a challenge was stored: `S256` recomputes
`base64url(sha256(code_verifier))`; `plain` compares the verifier as-is. Mismatch →
`INVALID_REQUEST` (400, `'PKCE verification failed'`).

Issues access + refresh tokens, and an **ID token if `scope` includes `openid`**. TTLs prefer
per-client overrides (`client.accessTokenTTL`/`refreshTokenTTL`) over `config.ttls.*`.

```json
{ "access_token": "...", "refresh_token": "...", "id_token": "...", "token_type": "Bearer", "expires_in": 3600, "scope": "openid profile" }
```

Errors: `MISSING_REQUIRED_FIELDS` (400); client-auth errors (below); `INVALID_REQUEST` (400, grant
not allowed / client_id or redirect_uri mismatch / PKCE failure); `INVALID_OR_EXPIRED_TOKEN` (400,
code unknown/used/expired — one code covers all three); `USER_NOT_ACTIVE` (400).

### `refresh_token`

Body adds: `refresh_token, client_id, client_secret?`. Atomically finds-and-revokes the presented
refresh token (rotation — old token cannot be reused after this call).

> **Scopes never widen beyond what the resource owner originally consented to.** The scopes granted
> at authorization time are carried on the session (`existing.claims.scopes`) and narrowed against
> the client's *current* `allowedScopes` on every refresh — `scopes = grantedScopes.filter(s => s
> === 'openid' || allowedScopes.has(s))`. So a refresh can only ever hold steady or shrink (e.g. if
> an admin later removes a scope from `client.allowedScopes`), never grant something broader than
> the original grant, even if the client's `allowedScopes` is expanded afterward. **No `id_token`
> is ever issued on refresh**, even when the original grant included `openid`.

```json
{ "access_token": "...", "refresh_token": "...", "token_type": "Bearer", "expires_in": 3600, "scope": "..." }
```

Errors: `MISSING_REQUIRED_FIELDS` (400); client-auth errors; `INVALID_REQUEST` (400, grant not
allowed); `INVALID_REFRESH_TOKEN` (400); `USER_NOT_ACTIVE` (400).

### `client_credentials`

Body adds: `client_id, client_secret, scope?`. **Confidential clients only** — rejected even if
`allowedGrants` includes it when `client.clientType !== 'confidential'`. If `scope` is omitted,
defaults to the client's **entire `allowedScopes` set** (not `[]`, not `openid`). Token's `sub`
claim is the client's own `clientId`, not a user id.

```json
{ "access_token": "...", "token_type": "Bearer", "expires_in": 3600, "scope": "..." }
```
No `refresh_token`, no `id_token` — confirmed per-spec.

### Client authentication (shared across all three grants)

Confidential clients must supply `client_secret` in the **request body** —
`token_endpoint_auth_methods_supported` in the [discovery document](jwks-oidc-discovery.md)
advertises `client_secret_basic` too, but nothing in this endpoint reads an `Authorization: Basic`
header; send the secret in the body regardless. Public clients authenticate with `client_id` alone.

Errors: `OAUTH_CLIENT_NOT_FOUND` (400, missing or not `ACTIVE`); `INVALID_REQUEST` (**401**, not
400 — confidential client omitted `client_secret`); `INVALID_CREDENTIALS` (401, secret mismatch).

## `POST /oauth2/token/revoke` (RFC 7009)

Body: `token, token_type_hint?, client_id?, client_secret?`.

> **Only refresh tokens are actually revocable here, regardless of `token_type_hint`.** The
> handler unconditionally hashes `token` and looks it up as a refresh token
> (`revokeByRefreshTokenHash`) — presenting an access-token JWT string as `token` simply hash-misses
> and no-ops. `token_type_hint` is accepted by the schema but never read by the handler.

`client_id` is optional; if supplied, the client authenticates (secret required for confidential
clients) but there's no check that the token being revoked actually belongs to that client. Always
returns `200 { status: 'ok' }` regardless of whether the token existed, per RFC 7009. If revoked,
writes a revocation-cache entry for the session's `jti`.

## `POST /oauth2/token/introspect` (RFC 7662)

Body: `{ token? }` — **`introspectTokenSchema` only accepts `token`**; no `client_id`/
`client_secret`/`token_type_hint`. **No client authentication is performed at all** — any caller
can introspect any refresh token. Like revocation, this **only ever introspects refresh tokens**,
never access-token JWTs — no JWT verification path runs here.

```json
{ "active": true, "sub": "...", "exp": 1234567890, "iat": 1234567890, "jti": "..." }
```
or `{ "active": false }`. Note the response omits `client_id`, `scope`, and `token_type` — fields
RFC 7662 lists as commonly present but optional; only `active`/`sub`/`exp`/`iat`/`jti` are ever
returned here.

## Client management — `POST/GET/PATCH/DELETE /oauth2/clients*`

> None of these six handlers check `req.auth` or `req.serviceCaller` themselves. `buildRouter()`
> mounts them **unauthenticated** — see [Router & Schemas](router-and-schemas.md). Gate them with
> your own admin middleware before exposing them.

- **`POST /oauth2/clients`** (self-registration, public) — body: `name, slug, clientType?,
  redirectUris (≥1, url), allowedScopes?, allowedGrants?, metadata?`. Defaults:
  `clientType: 'confidential'`, `allowedScopes: ['openid','email','profile']`, `allowedGrants:
  ['authorization_code','refresh_token']`. **Status is always forced to `PENDING_APPROVAL`** —
  there's no self-activation path. Returns the **only two places the raw `clientSecret` is ever
  exposed** (this call and rotate-secret): `201 { id, name, slug, clientId, clientSecret, status }`.
  `clientSecret` = 32 random bytes hex (64 chars), stored only as a bcrypt hash (12 rounds).
  `OAUTH_CLIENT_EXISTS` (409) if `slug` is taken.
- **`GET /oauth2/clients/:clientId`** → the raw stored client record as-is
  (`res.json(client)`) — confirm your storage adapter's `findByClientId` (without
  `includeSecret`) omits the secret hash by contract, since this handler does not redact it itself.
- **`GET /oauth2/clients`** → `{ clients, total, page, limit }` (`page` default 1, `limit` default
  20, clamped 1–100).
- **`PATCH /oauth2/clients/:clientId`** — accepts `name, redirectUris, allowedScopes,
  allowedGrants, clientType, accessTokenTTL, refreshTokenTTL, idTokenTTL, logoUrl, websiteUrl,
  privacyPolicyUrl, termsOfServiceUrl, supportEmail, metadata` (`updateOAuthClientSchema`, all
  optional). **`status` is not an updatable field through this schema** — see lifecycle note
  below. → `{ clientId, name, status }`.
- **`POST /oauth2/clients/:clientId/approve`** — `PENDING_APPROVAL → ACTIVE`. The only way out of
  pending approval.
- **`POST /oauth2/clients/:clientId/rotate-secret`** — issues a new secret, immediately
  invalidating the old one (no grace period/dual-secret support) → `{ clientId, clientSecret }`.
- **`DELETE /oauth2/clients/:clientId`** (deactivate) — `status → INACTIVE`.

All six: `OAUTH_CLIENT_NOT_FOUND` (404) if the client doesn't exist.

### Client status lifecycle

`ACTIVE | INACTIVE | SUSPENDED | PENDING_APPROVAL`. Registration always starts `PENDING_APPROVAL`
→ `approve` moves to `ACTIVE`. `deactivate` moves to `INACTIVE`. **`SUSPENDED` exists in the status
enum but no exported handler transitions a client into or out of it** — and `status` isn't in
`updateOAuthClientSchema`'s allowed fields, so it's unreachable through the public handler surface
as shipped. If you need it, set it via direct storage access.

## Consent management

- **`GET /oauth2/consent?client_id=...`** (auth required) → `{ client: { name, clientId, logoUrl,
  websiteUrl, privacyPolicyUrl }, existingConsent: { scopes, grantedAt } | null }`. Only checks
  client *existence*, not `status === ACTIVE` — a `PENDING_APPROVAL`/`INACTIVE` client's consent
  page is still viewable. `MISSING_REQUIRED_FIELDS` (400) if `client_id` omitted.
- **`GET /oauth2/consent/sessions`** (auth required) → array of `{ clientId, scopes, grantedAt,
  expiresAt }`.
- **`DELETE /oauth2/consent/sessions/:clientId`** (auth required) → `{ status: 'ok' }`
  (`ConsentRepository.revoke`, no existence check — revoking an unknown client no-ops).

## Related

- [OIDC](oidc.md) — ID tokens, UserInfo, discovery, RP-initiated logout.
- [Tokens & Signing (RS256)](tokens-rs256.md) — `issueOAuth2AccessToken`, `issueIdToken`.
- [Errors](errors.md)
- [OAuth2 Authorization Code Flow example](../examples/oauth2-authorization-code-flow.md)
