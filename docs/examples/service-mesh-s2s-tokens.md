---
title: "Service-to-Service Tokens (Service Mesh)"
package: "@okeav/idp-core"
category: "example"
tags: ["service-mesh", "internal-auth", "jwt"]
description: "Register two service identities, mint a short-lived S2S token from one to the other, and verify it both remotely and in-process."
---

# Service-to-Service Tokens (Service Mesh)

Lets your own backend services call each other with short-lived, cryptographically verifiable
tokens instead of a shared static secret. See [Service Mesh](../api/service-mesh.md) for the full
API reference. Adapted from the package's own `examples/e2e-test-harness`.

## Prerequisites

- A running idp-core server (the "IDP") with `config.serviceMesh.bootstrapSecrets` set — one
  registration secret per service.
- Two other services (or two code paths in one demo process, as below) that will register
  identities with the IDP.

## IDP config

```js
await initIdentityProvider({
  issuer: 'https://idp.example.com',
  // ...
  serviceMesh: {
    // One secret per service, provisioned out-of-band. Each covers only its own name, and lets that
    // service rotate its key. (With configFromEnv: IDP_S2S_BOOTSTRAP_SECRETS=orders-api=…,payments-api=…)
    // Each must be at least 32 characters (startup refuses shorter ones): openssl rand -base64 32
    bootstrapSecrets: {
      'orders-api': process.env.S2S_BOOTSTRAP_SECRET_ORDERS,
      'payments-api': process.env.S2S_BOOTSTRAP_SECRET_PAYMENTS,
    },
    allowedServiceNames: ['orders-api', 'payments-api'], // optional
    // tokenMode defaults to 'token' — only signed S2S JWTs are accepted.
    // rotationGraceSeconds: 3600, // default — how long a rotated-away key still verifies
  },
});
```

The legacy shared `bootstrapSecret` still works, but it can only register a name that has no key
yet: a second registration of an existing name with a different key answers 409
`SERVICE_NAME_TAKEN` (as do the losers of two *simultaneous* first registrations of one name —
their keys are revoked), and a name listed in `bootstrapSecrets` (like the two above) can't be
registered with it at all — 403 `FORBIDDEN`. Registration is rate limited per IP (`rateLimiting.serviceKeyRegistration`).

## Register two service identities

Each service generates its own RSA keypair and registers its public key with the IDP once at
startup:

```js
import crypto from 'crypto';
import { initServiceIdentity, mintServiceToken, verifyServiceTokenRemote } from '@okeav/idp-core';

function generateKeypair() {
  return crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
}

// If you mount buildRouter() under a prefix (e.g. `app.use('/auth', buildRouter())`),
// IDP_BASE_URL must include that prefix — initServiceIdentity/verifyServiceTokenRemote
// build their request URLs as `idpBaseUrl + '/internal/service-keys'` and
// `idpBaseUrl + '/.well-known/services-jwks.json'` with no awareness of where the
// router is actually mounted (same caveat as the `.well-known` note in
// router-and-schemas.md). This example assumes the router is mounted at `/`.
// It must be https — both functions refuse plain http except to localhost (or with NODE_ENV=development).
const IDP_BASE_URL = 'https://idp.example.com';

// Service "payments-api" registers itself at startup, with its own bootstrap secret:
const paymentsKeys = generateKeypair(); // RSA, at least 2048 bits — anything else is refused
await initServiceIdentity({
  serviceName: 'payments-api', // must match ^[a-z0-9][a-z0-9-]{0,62}$
  privateKeyPem: paymentsKeys.privateKey,
  idpBaseUrl: IDP_BASE_URL,
  bootstrapSecret: process.env.S2S_BOOTSTRAP_SECRET_PAYMENTS,
});
// -> { kid: 'payments-api:...' }

// ...and "orders-api" does the same in its own process:
const ordersKeys = generateKeypair();
await initServiceIdentity({
  serviceName: 'orders-api',
  privateKeyPem: ordersKeys.privateKey,
  idpBaseUrl: IDP_BASE_URL,
  bootstrapSecret: process.env.S2S_BOOTSTRAP_SECRET_ORDERS,
});
```

Registering a *new* keypair later under the same name with that service's own secret rotates it:
the old key moves to `ROTATING` — still accepted for `serviceMesh.rotationGraceSeconds` (default
3600), so in-flight tokens and instances still on the old key keep working — and is `RETIRED` on the
next rotation. To cut a key off immediately, call `revokeServiceKey(kid)` on the IDP. A revoked key
stays revoked: when the service restarts and re-registers it, `initServiceIdentity` fails with 409
`SERVICE_KEY_REVOKED` — generate a new keypair for it.

> `initServiceIdentity` sets **process-global state** — one active identity per process. In a real
> deployment, "orders-api" and "payments-api" are two separate running processes, each calling
> `initServiceIdentity` once with its own name/keypair. The snippet below simulates both in one
> process only for the sake of a runnable example.

## Mint a token

```js
// From orders-api, targeting payments-api:
const token = mintServiceToken('payments-api', { scopes: ['payments:charge'] });
// RS256 JWT, 60-second TTL (hardcoded — not configurable, see service-mesh.md), signed with
// orders-api's private key. { iss: 'orders-api', aud: 'payments-api', scope: 'payments:charge', ... }
```

Verifiers refuse a service token without `exp`, with an `iat` in the future, or with a lifetime
over 5 minutes. `scope` is whatever the caller wrote into its own token — nobody granted it, so
don't authorize on it alone.

## Verify it — over HTTP (payments-api doesn't run idp-core)

```js
try {
  const payload = await verifyServiceTokenRemote(token, {
    expectedAud: 'payments-api',
    idpBaseUrl: IDP_BASE_URL,
  });
  console.log('Verified S2S caller:', payload.iss, payload.scope);
} catch (err) {
  // err.code: SERVICE_TOKEN_INVALID | TOKEN_EXPIRED | SERVICE_UNAVAILABLE (no keys fetchable yet)
  console.error('Rejected:', err.code, err.message);
}
```

This fetches (and 5-minute-caches, per `idpBaseUrl`) `https://idp.example.com/.well-known/services-jwks.json`
— no per-request round trip to the IDP once cached. An unknown `kid` triggers a refresh at most
every 30 seconds, and a failed refresh keeps the last good keys.

## Verify it — in-process (payments-api also runs idp-core)

```js
import { serviceContextMiddleware, requireServiceCallerMiddleware } from '@okeav/idp-core';

app.post(
  '/internal/charge',
  serviceContextMiddleware({ ownServiceName: 'payments-api' }), // required: 500 SERVICE_NOT_CONFIGURED without it
  requireServiceCallerMiddleware('orders-api', 'billing-worker'), // name allowlist; refuses shared-secret callers
  (req, res) => {
    // req.serviceCaller = { name: 'orders-api', scopes: ['payments:charge'], region: 'global', source: 'token' }
    res.json({ charged: true });
  }
);
```

## Related

- [Service Mesh](../api/service-mesh.md) — full reference, including `tokenMode` semantics and the
  `req.serviceCaller` shape difference between token- and secret-verified callers.
- [Middleware](../api/middleware.md) — `serviceContextMiddleware`/`requireServiceCallerMiddleware`.
