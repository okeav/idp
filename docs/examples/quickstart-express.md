---
title: "Quickstart: Express Server"
package: "@okeav/idp-core"
category: "example"
tags: ["auth", "express", "mongodb", "quickstart"]
description: "Minimal runnable Express server wiring initIdentityProvider() and buildRouter() against a local Mongo replica set."
---

# Quickstart: Express Server

A complete, runnable identity server in one file. Based on the package's own
`examples/express-quickstart/`.

## Prerequisites

- Node ≥ 20
- A MongoDB **replica set** (a single-node one is enough — see
  [Repository Adapters](../api/repository-adapters.md) for why transactions require this).
  Easiest path: `docker compose up -d` using the `docker-compose.yml` shipped in the package repo,
  which starts a single-node replica set with `rs.initiate()` already run.
- `npm install @okeav/idp-core express cookie-parser`

## Code

```js
// server.js
import crypto from 'crypto';
import express from 'express';
import { initIdentityProvider, buildRouter, cookieParser } from '@okeav/idp-core';

// A real deployment generates this once and stores it durably (env var / secrets
// manager) — regenerating it on every boot invalidates all existing sessions.
const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

await initIdentityProvider({
  issuer: 'http://localhost:3000',
  mongo: { uri: 'mongodb://localhost:27017/idp-quickstart?replicaSet=rs0' },
  cache: { adapter: 'memory' }, // fine for a single process; see cache-interface.md for Redis

  signingKeys: { keys: { 'quickstart-key-1': { privateKey, publicKey, status: 'ACTIVE' } } },

  security: {
    // Generate real random secrets for anything beyond your own laptop.
    emailHashPepper: 'dev-only-pepper-do-not-use-in-prod',
    tokenHashSecret: 'dev-only-token-secret-do-not-use-in-prod',
  },

  hooks: {
    // No real mailer wired up — print what would have been sent.
    onVerificationEmailRequested: ({ email, verificationCode }) => {
      console.log(`[dev email] Verify ${email} — code: ${verificationCode}`);
    },
    onAuditLog: (event) => console.log(`[audit] ${event.action}`, event),
    // Called on every login (password/MFA/SSO/magic-link/WebAuthn) to build
    // the access token's opaque `claims` — a real app resolves role/permissions
    // from its own data model here.
    resolveAuthContext: async () => ({ claims: { role: 'member' } }),
  },
});

const app = express();
app.use(cookieParser());
app.use(express.json());
app.use('/auth', buildRouter());

// Every error this package throws is an IdpError — map it to your API's
// response shape in exactly one place. See errors.md.
app.use((err, req, res, next) => {
  res.status(err.httpStatus || 500).json({ error: err.code || 'INTERNAL_ERROR', message: err.message });
});

app.listen(3000, () => console.log('Listening on http://localhost:3000'));
```

## Try it

```bash
# Register
curl -X POST http://localhost:3000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"you@example.com","password":"Str0ng!Passw0rd"}'

# Server console prints: [dev email] Verify you@example.com — code: 123456

curl -X POST http://localhost:3000/auth/register/verify-email \
  -H "Content-Type: application/json" \
  -d '{"email":"you@example.com","code":"123456"}'

curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"you@example.com","password":"Str0ng!Passw0rd"}'
# -> { "accessToken": "...", "accessTokenExpiresAt": "...", "refreshToken": "...", "refreshTokenExpiresAt": "...", "userId": "..." }
```

## This is a quickstart, not a production config

- The signing key is regenerated every restart here — pin one via a persisted PEM for anything
  beyond a demo (see [Tokens & Signing](../api/tokens-rs256.md)).
- `emailHashPepper`/`tokenHashSecret` are placeholders — generate real random secrets.
- The `memory` cache/rate-limit adapters are single-instance only — switch to Redis before running
  more than one process (see [Redis Cache Adapter](redis-cache-adapter.md)).
- No HTTPS or CORS configured — that's Express's and your app's job, same as any Express server.

## Related

- [Bootstrap & Config](../api/bootstrap-config.md)
- [Password & Email Auth](../api/password-email-auth.md)
- [Router & Schemas](../api/router-and-schemas.md)
