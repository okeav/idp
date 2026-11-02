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
  bootstrapSecrets?: Record<string, string>;   // preferred: one registration secret per service name
  bootstrapSecret?: string;                    // legacy shared secret: can register a NEW name only (never one in bootstrapSecrets)
  allowedServiceNames?: string[];              // when set, only these names may register at all
  tokenMode?: 'token' | 'secret' | 'both';     // default 'token'
  ownServiceName?: string;                     // this service's own name (the `aud` it expects)
  sharedSecret?: string;                       // legacy fallback for the 'secret'/'both' modes
  allowLegacySecretCallers?: boolean;          // default false — see requireServiceCallerMiddleware
  rotationGraceSeconds?: number;               // default 3600 — how long a rotated-away (ROTATING) key still verifies
}
```

With `configFromEnv()`: `IDP_S2S_BOOTSTRAP_SECRETS` (`name=secret` pairs, comma-separated, e.g.
`billing=s1,orders=s2` — a malformed pair fails startup), `IDP_S2S_BOOTSTRAP_SECRET`,
`IDP_S2S_TOKEN_MODE` (default `token`) and `IDP_S2S_OWN_SERVICE_NAME`. `sharedSecret`,
`allowedServiceNames`, `allowLegacySecretCallers` and `rotationGraceSeconds` have no environment variable.

**Secret strength (checked at startup, 0.4.0):** `bootstrapSecret`, `sharedSecret` and every
`bootstrapSecrets` value must be at least 32 characters, and no per-service secret may equal the
shared `bootstrapSecret` — they decide who may register a key (and so mint tokens as that
service), or in `'secret'`/`'both'` mode who may call as a service. Generate each with
`openssl rand -base64 32`.

Prefer `bootstrapSecrets`. A per-service secret proves *which* service is registering, so it covers
only its own name and can rotate that name's key. The shared `bootstrapSecret` proves only "some
participating service": it can register a name that has no key yet, but never replace an existing
service's key (that would let any participant impersonate it), and never register a name that has
its own `bootstrapSecrets` entry at all (403 `FORBIDDEN`) — otherwise, once that service's key was
revoked, any participant could claim its name.

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
region }`. `idpBaseUrl` must be `https` (plain `http` only for `localhost`, `127.0.0.1`, `[::1]`, or any `http` with `NODE_ENV=development`, e.g. a docker-compose service name) —
the bootstrap secret is sent to it and its key set decides whose tokens are trusted; anything else
throws a plain `Error`.

`bootstrapSecret` solves the chicken-and-egg problem: a service can't mint a verifiable S2S JWT
before its public key is registered, so registration itself can't require one. Pass the service's
own entry from the IdP's `serviceMesh.bootstrapSecrets` (preferred), or the legacy shared
`serviceMesh.bootstrapSecret`, provisioned out-of-band. The key must be RSA of at least 2048 bits,
`serviceName` must match `^[a-z0-9][a-z0-9-]{0,62}$`, and `region` must be 1–32 characters of
`[A-Za-z0-9_-]` (see the handler below).

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

`scopes` are whatever the *calling* service chooses to put in its own token — nobody grants them.
Treat them as the caller's assertion, never as authorization on their own.

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
`<idpBaseUrl>/.well-known/services-jwks.json` (all timings hardcoded, not configurable):

- Keys are cached in memory for 5 minutes, **one cache per `idpBaseUrl`** for the life of the
  process (shared with `initServiceIdentity` for the same URL), so repeated calls don't refetch.
  Concurrent lookups during a refresh share one in-flight request.
- A `kid` not in the cache forces a refresh (the peer may just have rotated), but **at most once
  every 30 seconds** — a junk `kid`, which needs no credentials, can't make every request refetch.
- Fetches time out after 5 seconds and don't follow redirects. If a refresh fails, the last good
  keys keep being used and no new fetch is tried for 30 seconds. With no keys fetched yet at all,
  verification fails with `SERVICE_UNAVAILABLE` (503).

If `idpBaseUrl` is omitted, reuses the IdP URL set by `initServiceIdentity` — a pure-verifier
service that never calls `initServiceIdentity` must pass `idpBaseUrl` explicitly every call, or a
plain `Error` is thrown. The URL must be `https` (`http` only for localhost, or with `NODE_ENV=development`) — over plain http
anyone on the path could substitute the key set, and with it every service's identity; anything
else throws a plain `Error`.

Verification (shared with the in-process path below): decodes the JWT header for `kid`, looks up
the matching key (retrying once with a forced refresh on a miss), then `jwt.verify` with
`{ algorithms: ['RS256'], audience: expectedAud, clockTolerance: 30, maxAge: 300, issuer:
expectedIss (if provided) }`. On top of that, a token is refused unless it has an `exp`, an `iat`
that isn't in the future (beyond the 30 s tolerance), and a lifetime (`exp - iat`) of at most
**5 minutes** — a token that never expires, or claims to live longer, wasn't minted by a
well-behaved peer. **Independently of `expectedIss`**, also checks that the token's `iss` claim
matches the key's registered owner (`service` field in the JWKS entry) — catches a
forged/mismatched `iss` even when the caller didn't pass `expectedIss`.

Errors (all `IdpError`, 401 unless noted): `SERVICE_TOKEN_INVALID` (missing token, missing/unknown
`kid`, signature/audience/issuer mismatch, missing `exp`/`iat`, future `iat`, lifetime over 5
minutes, or `iss` doesn't match key owner); `TOKEN_EXPIRED` (expired specifically, distinguished
from other verify failures); `SERVICE_NOT_CONFIGURED` (500, `expectedAud` not passed);
`SERVICE_UNAVAILABLE` (503, no keys could be fetched).

## In-process verification — `serviceContextMiddleware`

See [Middleware](middleware.md#servicecontextmiddlewareopts) for the full signature. Uses the same
`verifyServiceTokenWith` core as `verifyServiceTokenRemote` (same lifetime rules), but looks up keys
**in-process** — one indexed read via `serviceKeyRepository.findPublishableByKid(kid)`, falling back
to scanning `listPublishable()` on an adapter without it — no HTTP round trip. A `ROTATING` key is
accepted only within `serviceMesh.rotationGraceSeconds` of its rotation (its `statusChangedAt`;
rows from before 0.4.0 fall back to `updatedAt`), the same rule the services JWKS applies. Note this in-process
path never passes `expectedIss` to the verifier — issuer enforcement here relies entirely on the
`iss`-vs-key-owner cross-check described above, not an explicit trusted-issuer allowlist.

It needs this service's own name (`opts.ownServiceName` or `config.serviceMesh.ownServiceName`) to
check the token's audience. Without one it answers 500 `SERVICE_NOT_CONFIGURED` (in every mode but
`'secret'`) — a missing name is a configuration error, never a reason to fall back to the shared
secret.

`req.serviceCaller` has **two different shapes depending on `source`** — don't assume both keys
are always present:
- `source: 'token'` → `{ name: payload.iss, scopes: string[], region, source: 'token' }` (`scopes`
  always an array, possibly empty — and caller-asserted, see `mintServiceToken`; `region` as the
  caller put it in its token).
- `source: 'legacy-secret'` → `{ name: <x-service-name header, unverified>, source: 'legacy-secret'
  }` — **no `scopes` or `region` keys at all.** If the `x-service-name` header is absent, `name`
  defaults to the literal string `'unknown'` rather than being omitted.

## `registerServiceKeyHandler` — `POST /internal/service-keys`

Mount behind `s2sBootstrapMiddleware` — this is what `buildRouter()` does for this route. The
middleware:

- rate limits per client IP (`rateLimiting.serviceKeyRegistration`, default 20 per 15 minutes,
  fail-closed: 503 `RATE_LIMITER_UNAVAILABLE` if the limiter backend errors);
- checks `x-s2s-bootstrap-secret` first against `bootstrapSecrets[body.name]`, then against the
  shared `bootstrapSecret`, comparing in constant time (both sides are hashed first, so neither the
  content nor the length of the secret leaks); 401 `UNAUTHENTICATED` on mismatch/missing.

Body: `{ name: string, publicKey: string (base64 PEM), region? }`. The handler then:

- requires `name` to match `^[a-z0-9][a-z0-9-]{0,62}$` and `region` (if given) to be 1–32
  characters of `[A-Za-z0-9_-]`;
- refuses a name not in `serviceMesh.allowedServiceNames`, when that is set (403 `FORBIDDEN`), a
  per-service secret presented for a different name (401 `UNAUTHENTICATED`), and the shared secret
  presented for a name that has its own `bootstrapSecrets` entry (403 `FORBIDDEN`, audited as
  `SERVICE_KEY_REGISTRATION_REFUSED` with `reason: 'name_has_own_secret'`);
- accepts only an **RSA public key of at least 2048 bits** — a private key PEM is refused (rotate
  it: it has left the service), as are non-RSA keys;
- refuses a key that was **revoked** with 409 `SERVICE_KEY_REVOKED` (audited as
  `SERVICE_KEY_REGISTRATION_REFUSED` with `reason: 'key_revoked'`) — a revoked key is never
  re-activated, even though every service re-registers its key at boot; the service must generate a
  new key pair. The check runs early when the repository has `findByKid`, and `upsertByKid`
  refuses a revoked kid again atomically — before any old key is demoted;
- is idempotent by `(name, publicKey)` → same derived `kid`, upserted;
- for a **new key under a name that already has one**: with that service's own per-service secret
  it's a rotation — the new key is registered **first**, then the name's `ACTIVE` keys move to
  `ROTATING` (still published and accepted for `serviceMesh.rotationGraceSeconds`, default 3600,
  after the rotation, so in-flight tokens and instances still on the old key keep working) and keys
  already `ROTATING` move to `RETIRED` — each only from the status just read
  (`setStatusByKid(kid, status, { expectedStatus })`), so a key revoked mid-rotation stays revoked;
  with the shared secret it's refused with 409 `SERVICE_NAME_TAKEN` (audited as
  `SERVICE_KEY_REGISTRATION_REFUSED`, `reason: 'name_taken'`);
- for **concurrent first registrations of one new name with the shared secret** (each saw "no key
  yet"): exactly one keeps the name — the `ACTIVE` key with the earliest `registeredAt` (then the
  lowest `kid`), i.e. the first one inserted: the Mongo adapter takes `registeredAt`,
  `statusChangedAt` and `lastSeenAt` from the **database** clock (`$$NOW`), not the app server's; every other registration revokes its own key and answers 409 `SERVICE_NAME_TAKEN`
  (so that service must generate a new key pair). A per-service secret rules this out.
  To move a shared-secret service to a new key, use its per-service secret, or `revokeServiceKey()`
  its old key first.

```json
{ "kid": "...", "name": "..." }
```
Status `201`; audited as `SERVICE_KEY_REGISTERED` (with `rotated`). Errors: `INVALID_REQUEST` (400)
for a bad `name`/`region`, a missing `publicKey`, or a key that isn't an RSA ≥ 2048-bit public key;
`UNAUTHENTICATED` (401); `FORBIDDEN` (403); `SERVICE_NAME_TAKEN` (409); `SERVICE_KEY_REVOKED` (409).

## `revokeServiceKey(kid)`

```ts
function revokeServiceKey(kid: string): Promise<boolean>
```

Programmatic, for your admin tooling (there is no HTTP route): marks the key `REVOKED`, so it is no
longer published in the services JWKS nor accepted in-process. Resolves `true` if a key was found
(audited as `SERVICE_KEY_REVOKED`). The revoked key itself can never be registered again
(409 `SERVICE_KEY_REVOKED`). Once a name has no publishable key left, it can be registered again
with a **new** key — by its own per-service secret, or by the shared secret if the name has no
`bootstrapSecrets` entry. Remote verifiers stop accepting the key when their cached JWKS next refreshes
(within 5 minutes).

## `getServicesJwksHandler` — `GET /.well-known/services-jwks.json`

**Public, unauthenticated by design** — keys are public by definition. Returns every
`ACTIVE` service key, and every `ROTATING` one still within `serviceMesh.rotationGraceSeconds` of
its rotation, that is an RSA public key (anything else — possible in rows written
before 0.4.0 — is skipped) as a JWK, with two **non-standard extension fields** added specifically
to support the cross-checks above: `service` (the registered service name) and `status`.
`Cache-Control: public, max-age=60`.

```json
{ "keys": [{ "kty": "RSA", "n": "...", "e": "...", "use": "sig", "alg": "RS256", "kid": "...", "service": "payments-api", "status": "ACTIVE" }] }
```

## `tokenMode` summary

| Mode | Behavior |
|---|---|
| `'token'` (default) | Only a cryptographic S2S JWT accepted; any verification failure is terminal, no fallback |
| `'secret'` | Only the `x-internal-service-secret` header (compared in constant time to `config.serviceMesh.sharedSecret`) is accepted; the caller's name comes from the **self-asserted, unverified** `x-service-name` header |
| `'both'` | Tries the token first if a bearer is present; on verification *failure* it logs a warning before falling back to the secret check — but a **missing** bearer falls back silently, with no warning logged |

Before 0.4.0 the default was `'both'` (also in `configFromEnv`). Use `'secret'`/`'both'` only for a
staged migration off the shared secret.

`requireServiceCallerMiddleware(...names)` (must run after `serviceContextMiddleware`) **refuses**
a caller whose `source === 'legacy-secret'` with 403 `FORBIDDEN` — anyone holding the shared secret
can claim any name in `x-service-name` — unless `config.serviceMesh.allowLegacySecretCallers: true`,
in which case the request proceeds and a warning is logged.

## Related

- [Middleware](middleware.md) — `serviceContextMiddleware`, `requireServiceCallerMiddleware`.
- [JWKS & OIDC Discovery](jwks-oidc-discovery.md) — the separate user-token JWKS endpoint.
- [Service Mesh S2S Tokens example](../examples/service-mesh-s2s-tokens.md)
