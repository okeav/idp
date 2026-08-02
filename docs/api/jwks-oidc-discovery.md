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

## `jwksHandler` — `GET /.well-known/jwks.json`

```ts
const jwksHandler: RequestHandler
```

Returns an RFC 7517 JWK Set built from every `ACTIVE`/`ROTATING` key in
`config.signingKeys.keys` (via `getVerifiableKeys` — see [Bootstrap & Config](bootstrap-config.md)
for key status semantics). `RETIRED` and `REVOKED` keys are **not** published here.

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

```json
{ "publicKey": "<base64 PEM>" }
```

Errors: `UNKNOWN_KID` (404, no such key); `KEY_NOT_ALLOWED` (403, key status is `REVOKED`).

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
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
  "scopes_supported": ["openid", "email", "profile"],
  "claims_supported": ["sub", "iss", "aud", "exp", "iat", "jti", "nonce", "email", "email_verified", "name", "given_name", "family_name", "picture", "locale", "zoneinfo", "updated_at"],
  "code_challenge_methods_supported": ["S256", "plain"],
  "request_parameter_supported": false,
  "claims_parameter_supported": false
}
```

> **Two discrepancies worth knowing about, not bugs to work around, just what the document
> currently says vs. does:**
> - `grant_types_supported` lists only `authorization_code` and `refresh_token` — it does **not**
>   list `client_credentials`, even though [`/oauth2/token`](oauth2-authorization-server.md)
>   accepts that grant. Likely intentional (client_credentials has no interactive/discovery
>   relevance for a browser-facing OIDC client), but a machine client relying strictly on this
>   document to enumerate supported grants would miss it.
> - `token_endpoint_auth_methods_supported` advertises `client_secret_basic` (HTTP Basic auth
>   header), but the token endpoint's `authenticateClient` only reads `client_id`/`client_secret`
>   from the **request body** — there is no `Authorization: Basic` header parsing in the shipped
>   controller. Send credentials in the body regardless of what this field advertises.

## Related

- [Tokens & Signing (RS256)](tokens-rs256.md) — the key registry these endpoints publish from.
- [Service Mesh](service-mesh.md) — the separate S2S JWKS endpoint.
- [OIDC](oidc.md) — the endpoints this discovery document points at.
