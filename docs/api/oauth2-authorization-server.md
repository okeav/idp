---
title: "OAuth2 Authorization Server"
package: "@okeav/idp-core"
category: "api-reference"
tags: ["oauth2", "authorization-server", "pkce"]
description: "Authorization code + PKCE (S256), client credentials, refresh token grants; client registration/lifecycle; consent; client-authenticated token revocation and introspection."
---

# OAuth2 Authorization Server

A full OAuth2 authorization-server surface: authorization-code grant with PKCE (S256, required by
default), client-credentials grant, refresh-token grant with rotation and reuse detection, client
registration/lifecycle, consent management, and RFC 7009/7662 revocation/introspection. See
[OIDC](oidc.md) for the ID-token/UserInfo/discovery layer built on top of this, and
[Tokens & Signing](tokens-rs256.md) for how tokens are signed.

## Grant support matrix

| Grant | Client type | Refresh token issued | ID token issued |
|---|---|---|---|
| `authorization_code` | confidential or public (PKCE always required for public clients) | yes | yes, if the granted scopes include `openid` |
| `refresh_token` | confidential or public | yes (rotated) | **no**, even if the original grant included `openid` |
| `client_credentials` | confidential only | no (per RFC 6749 §4.4) | no |

A client's own `allowedGrants` array is authoritative per-request — a client must be explicitly
provisioned with a grant even if the server supports it in principle (`UNAUTHORIZED_CLIENT`, 400,
if not listed).

## Who can use the tokens this server issues

Access tokens are classified by who they were issued to (see [Middleware](middleware.md) and
[Tokens & Signing](tokens-rs256.md)):

| Kind | Issued by | `sub` | `aud` | Extra claims |
|---|---|---|---|---|
| `first-party` | this IdP's own login / `/refresh` | user id | the issuer | — |
| `oauth2-user` | `authorization_code` / `refresh_token` grants | user id | the `client_id` | `client_id`, `scope` |
| `oauth2-client` | `client_credentials` grant | the `client_id` | the `client_id` | `client_id`, `scope`, `gty: 'client_credentials'` |

**An OAuth2 token is never a credential for the IdP's own routes.** `authContextMiddleware()` and
`verifyAccessToken()` accept only `first-party` tokens by default, so a relying party a user
authorized can't use its token to change the user's password, register a passkey or delete the
account. The only built-in route that takes an OAuth2 token is `GET /userinfo` (`oauth2-user`
only).

A resource server of your own that should accept tokens issued to OAuth2 clients opts in, and
must then check the granted scopes itself:

```js
import { authContextMiddleware } from '@okeav/idp-core';

app.get('/api/orders',
  authContextMiddleware({ accept: ['oauth2-user'] }), // add 'oauth2-client' for machine tokens
  (req, res, next) => {
    if (!req.auth.scopes?.includes('orders:read')) {
      return res.status(403).json({ error: 'INSUFFICIENT_SCOPE' });
    }
    next();
  },
  listOrders,
);
```

`req.auth.tokenKind` tells you which kind passed; `req.auth.clientId` and `req.auth.scopes` are
set for OAuth2 tokens. For an `oauth2-client` (client_credentials) token `req.auth.userId` is
`undefined` — there is no user; the client is `req.auth.clientId`.

## Authorization endpoint

**`GET /oauth2/authorize`** — query (`authorizeQuerySchema`): `client_id, redirect_uri,
response_type, scope?, state?, nonce?, code_challenge?, code_challenge_method?`. Mounted behind
`authContextMiddleware({ optional: true })` — it behaves differently for logged-in vs. anonymous
callers rather than requiring auth outright. It answers JSON (or a redirect), so your frontend
calls it with the user's session (cookie or Bearer) and acts on the result. OIDC `prompt` and
`max_age` are **not** supported — they're ignored, so an existing session is reused however old it
is; an RP that needs a fresh login checks the ID token's `auth_time` itself.

The request is validated **before** the login check, in this order — so an anonymous caller still
gets these errors:

1. `response_type` must be `code` → `INVALID_REQUEST` (400).
2. The client must exist and be `ACTIVE` → `OAUTH_CLIENT_NOT_FOUND` (400) — **also returned for a
   `PENDING_APPROVAL` client**, so the code alone can't distinguish "doesn't exist" from "not
   approved yet".
3. `redirect_uri` must exactly match one of `client.redirectUris` → `INVALID_REDIRECT_URI` (400).
4. Every requested scope must be in `client.allowedScopes` → `INVALID_REQUEST` (400). Scope
   defaults to `'openid'` if omitted. **`openid` is not implicitly allowed** — it must be listed
   in the client's `allowedScopes` like any other scope (the registration default,
   `['openid', 'email', 'profile']`, includes it).
5. PKCE (see below) → `INVALID_REQUEST` (400) if a required `code_challenge` is missing.

Then one of three outcomes:

1. **Not authenticated** → `401 { action: 'login_required' }` — your frontend sends the user
   through your own login UI and replays the same authorize URL afterwards.
2. **Missing consent** → `200 { action: 'consent_required', consent_challenge, client: { name,
   logoUrl, websiteUrl, privacyPolicyUrl }, scopes, missingScopes }` with `Cache-Control:
   no-store`. The whole validated request (client, redirect URI, scopes, `state`, `nonce`, PKCE
   challenge, and the user's `auth_time`) is stored server-side under `consent_challenge` — a
   single-use id bound to this user, valid for `ttls.authCode` (10 minutes by default). Show
   your consent screen and post the challenge to `/oauth2/authorize/confirm` or `/deny`.
3. **Already consented** to every requested scope (an unexpired consent record) → issues an
   authorization code and `302`-redirects to `redirect_uri?code=...&state=...&iss=<issuer>`.

Consent is scope-set-based (`missingScopes = requested − previously consented`) — there's no
separate "skip consent for first-party clients" flag; the only bypass is a prior matching consent
record, written by `POST /oauth2/authorize/confirm`.

Every authorization response (code or error) carries **`iss`** — the issuer (RFC 9207). Clients
should check it against the issuer they started the flow with, to detect authorization-server
mix-up.

### PKCE

- Only **`S256`** is accepted. `code_challenge` must be a 43-character base64url SHA-256 value,
  and a challenge must come with `code_challenge_method=S256` — an omitted method means `plain`
  per RFC 7636, so it is refused rather than assumed (`VALIDATION_ERROR`, 400).
- **Required for public clients, always.** For confidential clients it's governed by
  `config.oauth2.requirePkce`: `'all'` (default — every client, the RFC 9700 recommendation) or
  `'public'` (confidential clients may omit it). Any other value fails startup.
- At the token endpoint the verifier must be 43–128 unreserved characters and is compared in
  constant time. A `code_verifier` sent for a code issued **without** a challenge is refused (a
  PKCE downgrade, RFC 9700 §4.8.2).

### OIDC `nonce`

`nonce` (1–512 characters) is accepted **here**, stored with the authorization code, and echoed
into the ID token. A `nonce` sent to the token endpoint is ignored.

### `POST /oauth2/authorize/confirm` / `POST /oauth2/authorize/deny`

Auth required (`authContextMiddleware()`). Body: **only** `{ consent_challenge }` (strict schema —
any other field is a `VALIDATION_ERROR`). Neither endpoint takes the client, scopes or redirect
URI from the body: they act on exactly the request stored at authorize time, so a forged POST
(cross-site, or from a sibling origin) can't grant an arbitrary client arbitrary scopes. Being
state-changing cookie requests, they're also subject to the CSRF origin check (403
`CSRF_ORIGIN_REJECTED` unless the request comes from the issuer's origin or one of
`cookies.trustedOrigins` — see [Middleware](middleware.md)).

The challenge is taken atomically: it works once, and only for the user it was issued to.
Unknown, expired, already used, or another user's → `INVALID_CONSENT_CHALLENGE` (400; restart
authorization). The client is re-checked (it may have been deactivated, or its redirect URIs
changed, while the user decided) → `OAUTH_CLIENT_NOT_FOUND` / `INVALID_REDIRECT_URI` (400).

- **confirm** upserts consent with **exactly the stored scopes** (an upsert, not necessarily a
  union with prior consent — confirm against your storage adapter's `ConsentRepository.upsert`
  semantics if that distinction matters), issues a code and `302`-redirects —
  `redirect_uri?code=...&state=...&iss=...`. No JSON success body.
- **deny** `302`-redirects to `redirect_uri?error=access_denied&error_description=...&state=...&iss=...`.

## Token endpoint — `POST /oauth2/token`

`tokenSchema` (`.passthrough()`): `grant_type` must be `authorization_code`, `refresh_token` or
`client_credentials` — anything else fails schema validation (`VALIDATION_ERROR`, 400; the
handler's own `UNSUPPORTED_GRANT_TYPE` only applies if you mount `tokenHandler` without the
schema).

Every response from this endpoint (and from revoke/introspect) carries `Cache-Control: no-store`
and `Pragma: no-cache`. All three endpoints are rate limited per IP
(`rateLimiting.oauth2Token`, default 120/minute, fail-closed — 429 `RATE_LIMIT_EXCEEDED`, or 503
`RATE_LIMITER_UNAVAILABLE` if the limiter backend is down).

The router mounts no body parser. Spec-conformant clients send
`application/x-www-form-urlencoded` — mount `express.urlencoded({ extended: false })` (as well as
`express.json()`) before the router if you have such clients.

### Error responses

Errors are `IdpError`s passed to `next(err)`; with [`idpErrorHandler()`](errors.md) mounted they
answer `{ error, message }` with the RFC 6749 §5.2 error in **upper-case** form:

| `error` | Status | When |
|---|---|---|
| `INVALID_CLIENT` | 401 | any client-authentication failure (below) |
| `INVALID_GRANT` | 400 | code/refresh token unknown, used, expired, revoked, issued to another client; `redirect_uri` mismatch; PKCE failure; user not `ACTIVE`; refresh family past its absolute lifetime; a code issued before the user's sessions were revoked, or whose consent is gone, no longer covers its scopes, or was re-granted since |
| `INVALID_SCOPE` | 400 | `client_credentials` asked for a scope outside `allowedScopes` |
| `UNAUTHORIZED_CLIENT` | 400 | grant not in the client's `allowedGrants` |
| `UNSUPPORTED_GRANT_TYPE` | 400 | see above |
| `INVALID_REQUEST` | 400 | both HTTP Basic and a body `client_secret` sent |
| `MISSING_REQUIRED_FIELDS` | 400 | `code`/`redirect_uri` or `refresh_token` missing |
| `VALIDATION_ERROR` | 400 | schema failure (e.g. malformed `code_verifier`) |

### Client authentication (shared by token, revoke and introspect)

- **`client_secret_basic`** — `Authorization: Basic base64(client_id:client_secret)`, with both
  parts form-encoded first as RFC 6749 §2.3.1 requires (they're decoded before use).
- **`client_secret_post`** — `client_id` and `client_secret` in the body.
- **`none`** — public clients send `client_id` alone.

One method per request: Basic plus a body `client_secret` → `INVALID_REQUEST` (400); a body
`client_id` that differs from the Basic one → `INVALID_CLIENT`. A confidential client must present
its secret.

**Every failure — unknown client, inactive or not-yet-approved client, missing or wrong secret,
malformed Basic header — answers the same `401 INVALID_CLIENT`**, so the endpoint doesn't reveal
which client ids exist.

Client secrets are 256-bit random values, stored as `hmac-sha256:<hex>` keyed by
`security.tokenHashSecret` (a slow hash adds nothing for a random secret, and bcrypt's cost per
attempt was a cheap way to stall the server). Secrets stored as bcrypt by earlier versions still
verify and are re-stored as HMAC on their next successful use. Changing `tokenHashSecret`
therefore invalidates every HMAC-stored client secret.

### `authorization_code`

Body adds: `code, redirect_uri, code_verifier?` (+ client authentication). The code is
**atomically consumed** (single-use) via `consumeByCodeHash`; it must have been issued to the
authenticated client, and `redirect_uri` must match exactly what was used at authorize time.

**Code reuse detection.** If the code doesn't redeem and the adapter implements
`AuthorizationCodeRepository.findUsedByCodeHash`, a code that was *already* redeemed means
someone else holds it: everything its first redemption issued (the whole refresh-token family) is
revoked, and `OAUTH2_CODE_REUSE_DETECTED` is audited. The request itself fails `INVALID_GRANT`.

**A code dies with the sessions and the consent it came from** (0.4.0). The user must still be
`ACTIVE`, and the code is refused with `INVALID_GRANT` if the session that authorized it (the code
stores its access token's `jti`, `sessionJti`) has since been signed out or is gone — a sign-out
landing while `/authorize` was in flight. An ordinary refresh of that session doesn't count: a row
retired by rotation whose family still has a live row (`isFamilyLive`) keeps the code redeemable.
(A sessionless token — from the public `issueAccessToken()` export — binds no session to the code.)
It is also refused if it was issued at or before the user's
`sessionsRevokedAt` (logout-all, password reset/change, account deletion), or if the user's
consent for this client is missing, expired, doesn't cover the code's scopes, or was (re)granted
after the code was issued — so a code minted with a stolen session just before the victim signed
out everywhere, or withdrew consent, can't become a fresh long-lived session. After the new session
row is written, the redemption re-checks that the code wasn't replayed meanwhile (`reuseDetectedAt`,
the family tombstone) and that no "log out everywhere" landed while it ran; either way the new row
is revoked and the request fails (`INVALID_GRANT` / 401 `TOKEN_REVOKED`).

Issues an access token (`oauth2-user`) and a refresh token, plus an **ID token if the granted
scopes include `openid`** (see [OIDC](oidc.md#id-tokens) for its claims: `nonce` from the
authorize request, `azp`, `auth_time`, scope-gated profile/email claims). TTLs prefer per-client
overrides (`client.accessTokenTTL` / `refreshTokenTTL` / `idTokenTTL`) over `config.ttls.*`, clamped
at issuance to 24 h (access, ID) and 1 year (refresh) — `MAX_CLIENT_TTL_SECONDS`, which also covers
values stored before the schema cap. The
refresh token's session row is stored with `kind: 'oauth2'` and starts a new family rooted at the
code.

```json
{ "access_token": "...", "refresh_token": "...", "id_token": "...", "token_type": "Bearer", "expires_in": 3600, "scope": "openid profile" }
```

### `refresh_token`

Body adds: `refresh_token` (+ client authentication). Reads the presented refresh token's row and
runs every check below (client binding, user still `ACTIVE`, family lifetime) **before** consuming
it, so a refused refresh doesn't burn the token; then atomically finds-and-revokes it (rotation —
the old token cannot be used again).

- **Bound to its client.** Only a session row of kind `oauth2` issued to the authenticated client
  is accepted. A first-party refresh token (from `/login`), or another client's, fails
  `INVALID_GRANT` — and is revoked (reason `misused`, not a rotation), since presenting it here
  means it leaked. Conversely, the
  first-party `POST /refresh` refuses OAuth2 refresh tokens.
- **Reuse detection.** A token that was already rotated, presented again after
  `session.refreshReuseGraceSeconds` (default 10 s), revokes its whole family and emits
  `REFRESH_TOKEN_REUSE_DETECTED`; within the grace window the replay is only refused. A refresh
  racing that revocation is caught after it inserts its successor (`isFamilyRevoked`) and fails
  `TOKEN_REVOKED` (401).
- **Absolute lifetime.** A family ends `session.absoluteLifetimeSeconds` (default 90 days) after
  the code was redeemed, however actively it's refreshed; no refresh token's expiry extends past
  that, and a refresh after it fails `INVALID_GRANT`.
- A refresh that races a "log out everywhere" / password change for the same user is revoked and
  fails `TOKEN_REVOKED` (401).

> **Scopes never widen beyond what the resource owner originally consented to.** The scopes granted
> at authorization time are carried on the session (`claims.scopes`) and narrowed against the
> client's *current* `allowedScopes` on every refresh — `openid` included, with no special case.
> So a refresh can only hold steady or shrink, never grant something broader than the original
> grant. **No `id_token` is ever issued on refresh**, even when the original grant included `openid`.

```json
{ "access_token": "...", "refresh_token": "...", "token_type": "Bearer", "expires_in": 3600, "scope": "..." }
```

### `client_credentials`

Body adds: `scope?` (+ client authentication). **Confidential clients only** — a public client
gets `INVALID_CLIENT`. If `scope` is omitted, defaults to the client's **entire `allowedScopes`
set**; a scope outside it → `INVALID_SCOPE`. The token's `sub` is the client's own `clientId` and
it carries `gty: 'client_credentials'`, so it is classified `oauth2-client` and can never pass as
a user. No session row backs it, so it carries `sessionless: true` and can't be revoked
individually — but `authContextMiddleware` checks it against its **client** on every request: once
the client is deactivated (or deleted), its machine tokens get 401 `TOKEN_REVOKED` at once. (A
resource server that only calls `verifyAccessToken` doesn't get that check.) Its lifetime is the
client's `accessTokenTTL` (capped at 24 h, also at issuance) or `ttls.accessToken`.

```json
{ "access_token": "...", "token_type": "Bearer", "expires_in": 3600, "scope": "..." }
```
No `refresh_token`, no `id_token` — per spec.

## `POST /oauth2/token/revoke` (RFC 7009)

Body (strict): `token, token_type_hint?, client_id?, client_secret?`. **The client must
authenticate** (any method above; a public client by its `client_id`) — failure is
`401 INVALID_CLIENT`.

Handles both kinds of token (`token_type_hint` is accepted but not needed):

- a **refresh token** — revoked if it is an `oauth2` session issued to the calling client;
- an **access token** (JWT) — if it's an OAuth2 token issued to the calling client, its session
  row is revoked (ending the paired refresh token too) and its `jti` is marked revoked in the
  cache. A sessionless `client_credentials` token has nothing to revoke.

Tokens issued to other clients, first-party tokens and unknown tokens are silently ignored.
Always `200 { status: 'ok' }`, per RFC 7009. A revocation emits `OAUTH2_TOKEN_REVOKED`.

## `POST /oauth2/token/introspect` (RFC 7662)

Body (strict): `token, token_type_hint?, client_id?, client_secret?`. Callable only by an
authenticated **confidential** client (e.g. a resource server registered as a client); a public
client or any failure → `401 INVALID_CLIENT`. It describes **only tokens issued to the calling
client**; anything else — another client's, first-party, unknown, revoked, expired — is
`{ active: false }`.

Access token (JWT; its session row must still be live unless it's sessionless):

```json
{ "active": true, "token_type": "access_token", "client_id": "...", "sub": "...", "scope": "openid email", "exp": 0, "iat": 0, "iss": "...", "aud": "...", "jti": "..." }
```

Refresh token:

```json
{ "active": true, "token_type": "refresh_token", "client_id": "...", "sub": "<userId>", "scope": "openid email", "exp": 0, "iat": 0 }
```

## Client management — `POST/GET/PATCH/DELETE /oauth2/clients*`

> None of these seven handlers check `req.auth` or `req.serviceCaller` themselves. Since 0.3.0
> `buildRouter()` mounts them **only** when given `clientManagement: { middleware: [...] }` —
> your own admin auth, which runs before every one of them — and otherwise not at all (404). See
> [Router & Schemas](router-and-schemas.md). If you mount the handlers yourself, gate them the same
> way.
>
> ```js
> buildRouter({ clientManagement: { middleware: [requireAdmin] } }) // requireAdmin: your middleware
> ```

- **`POST /oauth2/clients`** (registration) — body (strict): `name, slug, clientType?,
  redirectUris (≥1), postLogoutRedirectUris?, allowedScopes?, allowedGrants?, metadata?`.
  Defaults: `clientType: 'confidential'`, `allowedScopes: ['openid','email','profile']`,
  `allowedGrants: ['authorization_code','refresh_token']`. **Status is always forced to
  `PENDING_APPROVAL`** — there's no self-activation path. Returns the **only two places the raw
  `clientSecret` is ever exposed** (this call and rotate-secret): `201 { id, name, slug, clientId,
  clientSecret, status }`. `clientSecret` = 32 random bytes hex (64 chars), stored only as an
  HMAC-SHA256 (see above). `OAUTH_CLIENT_EXISTS` (409) if `slug` is taken. If you leave `openid`
  out of a custom `allowedScopes`, the client can't run OIDC (and an authorize request with no
  `scope` fails, since the default scope is `openid`).
- **`GET /oauth2/clients/:clientId`** → the raw stored client record as-is
  (`res.json(client)`) — confirm your storage adapter's `findByClientId` (without
  `includeSecret`) omits the secret hash by contract, since this handler does not redact it itself.
- **`GET /oauth2/clients`** → `{ clients, total, page, limit }` (`page` default 1, `limit` default
  20, clamped 1–100).
- **`PATCH /oauth2/clients/:clientId`** — accepts `name, redirectUris, postLogoutRedirectUris,
  allowedScopes, allowedGrants, clientType, accessTokenTTL, refreshTokenTTL, idTokenTTL, logoUrl,
  websiteUrl, privacyPolicyUrl, termsOfServiceUrl, supportEmail, metadata`
  (`updateOAuthClientSchema`, strict, all optional). `accessTokenTTL` and `idTokenTTL` are capped
  at 86400 (24 h) and `refreshTokenTTL` at 31536000 (1 year) — an access token can't be revoked
  once issued, so a ten-year TTL would be a ten-year credential; `logoUrl`, `websiteUrl`,
  `privacyPolicyUrl` and `termsOfServiceUrl` must be `https` URLs (they're links on the consent
  screen — a `javascript:` URL there would run in the IdP's origin). **`status` is not an updatable field through
  this schema** — see lifecycle note below. → `{ clientId, name, status }`.
- **`POST /oauth2/clients/:clientId/approve`** — `PENDING_APPROVAL → ACTIVE`. The only way out of
  pending approval.
- **`POST /oauth2/clients/:clientId/rotate-secret`** — issues a new secret, immediately
  invalidating the old one (no grace period/dual-secret support) → `{ clientId, clientSecret }`.
- **`DELETE /oauth2/clients/:clientId`** (deactivate) — `status → INACTIVE`, and **revokes every
  session issued to the client, for every user** (and marks the paired access tokens revoked), so
  the client keeps nothing it was issued → `{ clientId, status }`. Its `client_credentials` tokens
  stop at `authContextMiddleware` too (they have no session). Needs the adapter's
  `SessionRepository.revokeForClient`; without it a warning is logged and the tokens are left
  alone.

The five `/:clientId` routes: `OAUTH_CLIENT_NOT_FOUND` (404) if the client doesn't exist.

### Redirect URI rules

`redirectUris` and `postLogoutRedirectUris` (on register and update) must each be:

- `https:` with a host; or
- `http:` **only** to a loopback host (`localhost`, `127.0.0.1`, `[::1]` — native apps and local
  development, RFC 8252 §7.3); or
- a reverse-DNS private-use scheme for native apps, e.g. `com.example.app:/callback` (RFC 8252
  §7.1 — the scheme must contain a dot);

and never contain a fragment (`#`) or embedded credentials (`user:pass@`), or exceed 2048
characters. `javascript:`, `data:`, `file:` and every other scheme are refused
(`VALIDATION_ERROR`, 400). At authorize time the `redirect_uri` must then match a registered one
exactly.

### Client status lifecycle

`ACTIVE | INACTIVE | SUSPENDED | PENDING_APPROVAL`. Registration always starts `PENDING_APPROVAL`
→ `approve` moves to `ACTIVE`. `deactivate` moves to `INACTIVE`. **`SUSPENDED` exists in the status
enum but no exported handler transitions a client into or out of it** — and `status` isn't in
`updateOAuthClientSchema`'s allowed fields, so it's unreachable through the public handler surface
as shipped. If you need it, set it via direct storage access (and revoke the client's sessions
yourself — only `deactivate` does that). A non-`ACTIVE` client can't authorize, redeem tokens or
authenticate to revoke/introspect.

## Consent management

- **`GET /oauth2/consent?client_id=...`** (auth required) → `{ client: { name, clientId, logoUrl,
  websiteUrl, privacyPolicyUrl }, existingConsent: { scopes, grantedAt } | null }`. The query is
  validated (strict, `client_id` a non-empty string — operator objects like `?client_id[$ne]=`
  are refused with `VALIDATION_ERROR`). A client that doesn't exist **or isn't `ACTIVE`** →
  `OAUTH_CLIENT_NOT_FOUND` (400).
- **`GET /oauth2/consent/sessions`** (auth required) → array of `{ clientId, scopes, grantedAt,
  expiresAt }`.
- **`DELETE /oauth2/consent/sessions/:clientId`** (auth required) → `{ status: 'ok' }`. Revokes the
  consent record (`ConsentRepository.revoke`, no existence check — revoking an unknown client
  no-ops) **and** the client's sessions for this user (`SessionRepository.revokeForClient(clientId,
  { userId })`), with their access tokens, and any of its authorization codes not yet redeemed
  (refused at `/oauth2/token`) — withdrawing consent ends what it authorized. Emits
  `CONSENT_REVOKED` with `revokedSessions`.

These routes take the user's first-party session; the `DELETE` is subject to the CSRF origin
check when cookie-authenticated.

## Related

- [OIDC](oidc.md) — ID tokens, UserInfo, discovery, RP-initiated logout.
- [Tokens & Signing (RS256)](tokens-rs256.md) — `issueOAuth2AccessToken`, `issueIdToken`.
- [Middleware](middleware.md) — `authContextMiddleware({ accept })`, token kinds, CSRF.
- [Errors](errors.md) — `idpErrorHandler()` and the error codes above.
- [OAuth2 Authorization Code Flow example](../examples/oauth2-authorization-code-flow.md)
