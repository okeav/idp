---
title: "Service Mesh (S2S JWKS Trust)"
package: "@okeav/idp-core"
category: "api-reference"
tags: ["service-mesh", "jwt", "internal-auth"]
description: "Register per-service signing keys with this IDP and mint/verify short-lived RS256 service-to-service tokens, in-process or over HTTP."
---

# Service Mesh (S2S JWKS Trust)

A differentiator kept from the source this package was extracted from: any number of your own
backend services can register an S2S signing keypair with this IDP and mint short-lived RS256
tokens to call each other — verified either in-process (if the verifying service also runs this
package) or over HTTP against a published JWKS endpoint (for services that don't). This is a
**separate key system** from the user-token signing keys in `config.signingKeys` — see
[JWKS & OIDC Discovery](jwks-oidc-discovery.md).

## `config.serviceMesh`

```ts
{
  bootstrapSecret?: string;                    // shared value for the one-time key-registration call
  tokenMode?: 'token' | 'secret' | 'both';      // default 'both'
  ownServiceName?: string;
  sharedSecret?: string;                        // legacy fallback for the 'secret'/'both' modes
}
```

## `initServiceIdentity(opts)`

```ts
function initServiceIdentity(opts: {
  serviceName: string; privateKeyPem: string; region?: string; // default 'global'
  idpBaseUrl: string; bootstrapSecret: string;
}): Promise<{ kid: string }>
```

Sets **process-global singleton state** — calling this again overwrites the active identity;
there's no support for multiple concurrent service identities in one process.

Derives the public key from `privateKeyPem`, computes a deterministic `kid` (`<serviceName>:<first
16 hex chars of sha256({e,kty,n})>` — same keypair + same name always yields the same `kid`, which
is what makes registration idempotent), then `POST`s to `<idpBaseUrl>/internal/service-keys` with
header `x-s2s-bootstrap-secret: <bootstrapSecret>` and body `{ name, publicKey: <base64 PEM>,
region }`.

`bootstrapSecret` solves the chicken-and-egg problem: a service can't mint a verifiable S2S JWT
before its public key is registered, so registration itself can't require one. It's a shared
value every participating service is preconfigured with out-of-band.

Throws plain `Error` (not `IdpError`) for missing required fields or a non-OK registration
response — these are startup/config failures, not request-time errors.

## `mintServiceToken(targetService, opts?)` (alias: `issueServiceToken`)

```ts
function mintServiceToken(targetService: string, opts?: { scopes?: string[] }): string
```

Signs an RS256 JWT with the active identity's private key: `{ iss: <own serviceName>, aud:
targetService, iat, exp, jti, region, scope?: scopes.join(' ') }`.

> **TTL is a hardcoded 60 seconds** (`TOKEN_TTL_SECONDS`), **not** wired to
> `config.ttls.internalToken` (which defaults to 30s but is unused by this code path) — the S2S
> token lifetime is not configurable through the public config surface as shipped. Design your S2S
> call patterns around a fixed 1-minute token lifetime (plus a 30-second verification-side clock
> tolerance — see below), or mint a fresh token per call rather than caching one.

Throws plain `Error` if `initServiceIdentity` was never called, or `targetService` is falsy.

## `getServiceIdentity()`

```ts
function getServiceIdentity(): { serviceName: string; kid: string; region: string }
```

Reads the module-level singleton, synchronously. Deliberately omits the private/public key
material — those stay internal. Throws plain `Error` if `initServiceIdentity` hasn't run.

## `verifyServiceTokenRemote(token, opts)`

```ts
function verifyServiceTokenRemote(token: string, opts: {
  expectedAud: string; expectedIss?: string; idpBaseUrl?: string;
}): Promise<Record<string, unknown>>
```

For a service that doesn't run this package's storage/state (pure verifier). Fetches and caches
`<idpBaseUrl>/.well-known/services-jwks.json` (5-minute in-memory cache, hardcoded, not
configurable; concurrent lookups during a refresh share one in-flight request). If `idpBaseUrl` is
omitted, reuses the identity set by `initServiceIdentity` — a pure-verifier service that never
calls `initServiceIdentity` must pass `idpBaseUrl` explicitly every call, or a plain `Error` is
thrown.

Verification (shared with the in-process path below): decodes the JWT header for `kid`, looks up
the matching key (retrying once with a forced cache refresh on a miss, in case the peer just
rotated), then `jwt.verify` with `{ algorithms: ['RS256'], audience: expectedAud, clockTolerance:
30, issuer: expectedIss (if provided) }`. **Independently of `expectedIss`**, also checks that the
token's `iss` claim matches the key's registered owner (`service` field in the JWKS entry) —
catches a forged/mismatched `iss` even when the caller didn't pass `expectedIss`.

Errors (all `IdpError`, 401 unless noted): `SERVICE_TOKEN_INVALID` (missing token, missing/unknown
`kid`, signature/audience/issuer mismatch, or `iss` doesn't match key owner);
`TOKEN_EXPIRED` (401, expired specifically, distinguished from other verify failures).

## In-process verification — `serviceContextMiddleware`

See [Middleware](middleware.md#servicecontextmiddlewareopts) for the full signature. Uses the same
`verifyServiceTokenWith` core as `verifyServiceTokenRemote`, but looks up keys **in-process**
against `state.storage.serviceKeyRepository.listPublishable()` — no HTTP round trip. Note this
in-process path never passes `expectedIss` to the verifier — issuer enforcement here relies
entirely on the `iss`-vs-key-owner cross-check described above, not an explicit trusted-issuer
allowlist.

`req.serviceCaller` has **two different shapes depending on `source`** — don't assume both keys
are always present:
- `source: 'token'` → `{ name: payload.iss, scopes: string[], region, source: 'token' }` (`scopes`
  always an array, possibly empty; `region` always present).
- `source: 'legacy-secret'` → `{ name: <x-service-name header, unverified>, source: 'legacy-secret'
  }` — **no `scopes` or `region` keys at all.** If the `x-service-name` header is absent, `name`
  defaults to the literal string `'unknown'` rather than being omitted.

## `registerServiceKeyHandler` — `POST /internal/service-keys`

Mount behind `s2sBootstrapMiddleware` (checks `x-s2s-bootstrap-secret` against
`config.serviceMesh.bootstrapSecret`, strict equality, 401 `UNAUTHENTICATED` on mismatch/missing —
this is what `buildRouter()` does for this route). Body: `{ name: string, publicKey: string
(base64 PEM), region? }`. Validates the key actually parses (`crypto.createPublicKey`).
Idempotent by `(name, publicKey)` → same derived `kid`, upserted.

```json
{ "kid": "...", "name": "..." }
```
Status `201`. Errors: `INVALID_REQUEST` (400) for missing `name`/`publicKey` or an unparseable key.

## `getServicesJwksHandler` — `GET /.well-known/services-jwks.json`

**Public, unauthenticated by design** — keys are public by definition. Returns every
`ACTIVE`/`ROTATING` service key as a JWK, with two **non-standard extension fields** added
specifically to support the cross-checks above: `service` (the registered service name) and
`status`. `Cache-Control: public, max-age=60`.

```json
{ "keys": [{ "kty": "RSA", "n": "...", "e": "...", "use": "sig", "alg": "RS256", "kid": "...", "service": "payments-api", "status": "ACTIVE" }] }
```

## `tokenMode` summary

| Mode | Behavior |
|---|---|
| `'token'` | Only a cryptographic S2S JWT accepted; any verification failure is terminal, no fallback |
| `'secret'` | Only the `x-internal-service-secret` header (compared to `config.serviceMesh.sharedSecret`) is accepted; the caller's name comes from the **self-asserted, unverified** `x-service-name` header |
| `'both'` (default) | Tries the token first if a bearer is present; on verification *failure* it logs a warning before falling back to the secret check — but a **missing** bearer falls back silently, with no warning logged |

`requireServiceCallerMiddleware(...names)` (must run after `serviceContextMiddleware`) logs a
warning — not an error, the request still proceeds — whenever `caller.source === 'legacy-secret'`,
recommending `tokenMode: 'token'` for production.

## Related

- [Middleware](middleware.md) — `serviceContextMiddleware`, `requireServiceCallerMiddleware`.
- [JWKS & OIDC Discovery](jwks-oidc-discovery.md) — the separate user-token JWKS endpoint.
- [Service Mesh S2S Tokens example](../examples/service-mesh-s2s-tokens.md)
