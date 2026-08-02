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

- A running idp-core server (the "IDP") with `config.serviceMesh.bootstrapSecret` set.
- Two other services (or two code paths in one demo process, as below) that will register
  identities with the IDP.

## IDP config

```js
await initIdentityProvider({
  issuer: 'https://idp.example.com',
  // ...
  serviceMesh: {
    bootstrapSecret: process.env.S2S_BOOTSTRAP_SECRET, // shared, preconfigured out-of-band
    tokenMode: 'token', // 'both' (default) also accepts a legacy shared-secret fallback
  },
});
```

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
const IDP_BASE_URL = 'https://idp.example.com';
const BOOTSTRAP_SECRET = process.env.S2S_BOOTSTRAP_SECRET;

// Service "payments-api" registers itself at startup:
const paymentsKeys = generateKeypair();
await initServiceIdentity({
  serviceName: 'payments-api',
  privateKeyPem: paymentsKeys.privateKey,
  idpBaseUrl: IDP_BASE_URL,
  bootstrapSecret: BOOTSTRAP_SECRET,
});
// -> { kid: 'payments-api:...' }
```

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

## Verify it — over HTTP (payments-api doesn't run idp-core)

```js
try {
  const payload = await verifyServiceTokenRemote(token, {
    expectedAud: 'payments-api',
    idpBaseUrl: IDP_BASE_URL,
  });
  console.log('Verified S2S caller:', payload.iss, payload.scope);
} catch (err) {
  // err.code: SERVICE_TOKEN_INVALID | TOKEN_EXPIRED
  console.error('Rejected:', err.code, err.message);
}
```

This fetches (and 5-minute-caches) `https://idp.example.com/.well-known/services-jwks.json` — no
per-request round trip to the IDP once cached.

## Verify it — in-process (payments-api also runs idp-core)

```js
import { serviceContextMiddleware, requireServiceCallerMiddleware } from '@okeav/idp-core';

app.post(
  '/internal/charge',
  serviceContextMiddleware({ ownServiceName: 'payments-api' }),
  requireServiceCallerMiddleware('orders-api', 'billing-worker'), // name allowlist
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
