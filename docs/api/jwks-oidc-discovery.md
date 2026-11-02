---
title: "JWKS & OIDC Discovery"
package: "@okeav/idp-core"
category: "api-reference"
tags: ["oidc", "jwks", "discovery"]
description: "jwksHandler, authPublicKeyHandler, and openidConfigurationHandler — how this IDP's user-token signing keys are published."
---

# JWKS & OIDC Discovery

Publishes this IDP's **own user-token signing keys** (access/ID/OAuth2 tokens — RS256, from
`config.signingKeys.keys`) for external verification, plus the OIDC discovery document. This is
distinct from the [service-mesh JWKS](service-mesh.md) (`/.well-known/services-jwks.json`), which
publishes a separate set of per-service S2S keys.

These are the only responses from `buildRouter()` that may be cached: everything else is sent with
`Cache-Control: no-store`.

## `jwksHandler` — `GET /.well-known/jwks.json`

```ts
const jwksHandler: RequestHandler
```

Returns an RFC 7517 JWK Set built from every `ACTIVE`/`ROTATING` key in
`config.signingKeys.keys` (via `getVerifiableKeys` — see [Bootstrap & Config](bootstrap-config.md)
for key status semantics). `RETIRED` and `REVOKED` keys are **not** published here. Sent with
`Cache-Control: public, max-age=300`, so a rotation propagates to relying parties within five
minutes.

```json
{ "keys": [{ "kty": "RSA", "n": "...", "e": "...", "use": "sig", "alg": "RS256", "kid": "..." }] }
```

## `authPublicKeyHandler` — `GET /keys/:kid`

```ts
const authPublicKeyHandler: RequestHandler
```

Returns the raw base64 PEM for a single key by `kid` — for internal resource servers that want the
PEM directly instead of parsing a JWK. Unlike the JWKS endpoint, this **also serves `RETIRED`**
keys (still needed to verify not-yet-expired tokens signed before rotation), but not `REVOKED`.
Sent with `Cache-Control: public, max-age=300`.

```json
{ "publicKey": "<base64 PEM>" }
```

Errors: `UNKNOWN_KID` (404, no such key); `KEY_NOT_ALLOWED` (403, key status is `REVOKED`).

> Verifying a token yourself with these keys checks the signature only. To tell a first-party
> token from one issued to an OAuth2 client, check `client_id`/`aud` the way
> [`verifyAccessToken`](tokens-rs256.md#access-token-kinds) does.

## `openidConfigurationHandler` — `GET /.well-known/openid-configuration`

```ts
const openidConfigurationHandler: RequestHandler
```

Returns the OIDC discovery document, all endpoints derived from `config.issuer`. Sets
`Cache-Control: public, max-age=<config.ttls.discoveryCache>` (default 3600s).

```json
{
  "issuer": "https://idp.example.com",
  "authorization_endpoint": "https://idp.example.com/oauth2/authorize",
  "token_endpoint": "https://idp.example.com/oauth2/token",
  "userinfo_endpoint": "https://idp.example.com/userinfo",
  "jwks_uri": "https://idp.example.com/.well-known/jwks.json",
  "end_session_endpoint": "https://idp.example.com/oidc/end-session",
  "revocation_endpoint": "https://idp.example.com/oauth2/token/revoke",
  "introspection_endpoint": "https://idp.example.com/oauth2/token/introspect",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
  "revocation_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
  "introspection_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
  "scopes_supported": ["openid", "email", "profile"],
  "claims_supported": ["sub", "iss", "aud", "azp", "exp", "iat", "jti", "nonce", "auth_time", "email", "email_verified", "name", "given_name", "family_name", "picture", "locale", "zoneinfo", "updated_at"],
  "code_challenge_methods_supported": ["S256"],
  "prompt_values_supported": ["none", "login", "consent", "select_account"],
  "authorization_response_iss_parameter_supported": true,
  "request_parameter_supported": false,
  "claims_parameter_supported": false
}
```

Notes on what the document advertises:

- **Client authentication.** `client_secret_basic` (HTTP Basic, RFC 6749 §2.3.1 — form-encoded
  id and secret) and `client_secret_post` (body) are both implemented; a request may use only one.
  `none` is for public clients (PKCE). Introspection requires a confidential client. See
  [OAuth2 Authorization Server](oauth2-authorization-server.md).
- **PKCE.** Only `S256` — `plain` is refused, and a `code_challenge` must come with
  `code_challenge_method=S256`.
- **`prompt_values_supported`.** `/oauth2/authorize` honours these `prompt` values, and `max_age`
  (`select_account` behaves as `login`). See
  [OAuth2 Authorization Server](oauth2-authorization-server.md#prompt-and-max_age).
- **`end_session_endpoint`.** A `GET` from a signed-in browser without an `id_token_hint` asks for
  confirmation (`POST` to the same URL) instead of ending the session — see
  [OIDC](oidc.md#get--post-oidcend-session--endsessionhandler).
- **`authorization_response_iss_parameter_supported`.** Authorization responses carry an `iss`
  parameter (RFC 9207); clients should check it equals `issuer`.
- **Claims** in an ID token follow the granted scopes (`email` → `email`, `email_verified`;
  `profile` → `name`, `given_name`, `family_name`, `picture`, `locale`, `zoneinfo`); `azp` and
  `auth_time` are always present (`auth_time` when the login time is known). See
  [OIDC](oidc.md).
- **`openid`** is listed in `scopes_supported`, but a client still gets it only if its own
  `allowedScopes` includes it.

## Related

- [Tokens & Signing (RS256)](tokens-rs256.md) — the key registry these endpoints publish from.
- [Service Mesh](service-mesh.md) — the separate S2S JWKS endpoint.
- [OIDC](oidc.md) — the endpoints this discovery document points at.
