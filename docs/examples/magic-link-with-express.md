---
title: "Magic Link Login with Express"
package: "@okeav/idp-core"
category: "example"
tags: ["auth", "magic-link", "passwordless", "express"]
description: "Wire passwordless email login end-to-end: request a link, email it via your own mailer hook, verify on click."
---

# Magic Link Login with Express

Passwordless login via a one-time emailed link. This package never sends email itself — you wire
your mailer inside the `onMagicLinkRequested` hook.

## Prerequisites

- A running idp-core server (see [Quickstart: Express Server](quickstart-express.md)).
- Your own mail-sending function (this example uses a stub `sendEmail`).

## Server setup

Add the hook when calling `initIdentityProvider()`:

```js
import express from 'express';
import { initIdentityProvider, buildRouter, cookieParser, idpErrorHandler } from '@okeav/idp-core';

await initIdentityProvider({
  issuer: 'http://localhost:3000',
  mongo: { uri: 'mongodb://localhost:27017/idp?replicaSet=rs0' },
  signingKeys: { keys: { 'k1': { privateKey, publicKey, status: 'ACTIVE' } } },
  security: { emailHashPepper: '...', tokenHashSecret: '...' }, // each random, ≥ 32 characters
  mfa: { encryptionKey: process.env.IDP_MFA_ENCRYPTION_KEY }, // or mfa: { enabled: false }

  // Invite-only apps: set false so an unrecognized email silently no-ops
  // instead of creating a new account via magic link.
  magicLink: { allowSignupViaMagicLink: true },

  hooks: {
    // Started but not awaited by the request handler (so the response time doesn't reveal whether
    // the address has an account); errors are logged. In serverless runtimes, enqueue here
    // rather than sending inline.
    onMagicLinkRequested: async ({ email, magicLinkToken, isNewUser }) => {
      const url = `https://app.example.com/magic-link/verify?token=${magicLinkToken}`;
      await sendEmail(email, isNewUser
        ? `Welcome! Click to finish signing up: ${url}`
        : `Click to log in: ${url}`);
    },
    resolveAuthContext: async () => ({ claims: { role: 'member' } }),
  },
});

const app = express();
app.use(cookieParser());
app.use(express.json());
app.use('/auth', buildRouter());
app.use(idpErrorHandler()); // after the router: { error, message } for client errors, no internals on 500s
app.listen(3000);
```

Sending the email from a webhook receiver instead of the in-process hook? The `magicLinkToken`
field is stripped from webhook deliveries unless that endpoint sets `includeCredentials: true` —
see [Webhooks](../api/webhooks.md).

## Request a link

```js
const BASE = 'http://localhost:3000/auth';

async function requestMagicLink(email) {
  const res = await fetch(`${BASE}/magic-link/request`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email }),
  });
  return res.json(); // always { status: 'ok' } regardless of whether the email exists —
                      // see magic-link.md for the full enumeration-safety behavior
}
```

This is rate-limited by default to 3 requests per hour per IP (`config.rateLimiting.magicLink`)
**and** 3 per hour per address (`config.rateLimiting.magicLinkByEmail`) — see
[Rate Limiter Interface](../api/rate-limiter-interface.md). Requesting a new link invalidates the
earlier ones, so only the most recent email works.

## Verify on click

Your frontend route at `/magic-link/verify` (matching the URL built in the hook above) extracts
`token` from its own query string and calls the API:

```js
async function verifyMagicLink(token) {
  const res = await fetch(`${BASE}/magic-link/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token }),
    credentials: 'include', // accept the session cookies
  });
  if (!res.ok) {
    const err = await res.json();
    // err.error === 'INVALID_OR_EXPIRED_TOKEN' if the link was already used, expired, or
    // superseded by a newer one (the link is single-use — a second click always fails).
    throw err;
  }
  const body = await res.json();
  if (body.mfaRequired) {
    // The account has MFA: no session yet. Ask for a TOTP/recovery code (or a passkey) and complete
    // the login at POST /mfa/verify (or /webauthn/mfa/verify) with body.mfaChallengeToken,
    // within body.expiresIn seconds — exactly as after a password login.
    return { mfaRequired: true, mfaChallengeToken: body.mfaChallengeToken, expiresIn: body.expiresIn };
  }
  return body; // { accessToken, accessTokenExpiresAt, refreshToken, refreshTokenExpiresAt, userId, isNewUser }
}
```

See [MFA TOTP Setup & Verify](mfa-totp-setup-and-verify.md) for the `/mfa/verify` call.

`isNewUser: true` in the response tells your frontend this was a first-time signup via magic
link — useful for routing to an onboarding flow vs. a normal post-login redirect. Activating a
not-yet-verified account this way discards any password set on it before the address was proven,
so a user who registered with a password but verified through a magic link sets a new one via
password reset.

Testing this against `http://localhost` in a real browser (not just `curl`)? See
[`cookies.secure` and local browser testing](../api/bootstrap-config.md#cookiessecure-and-local-browser-testing)
— the `credentials: 'include'` cookie path above silently fails in a real browser, without an
error anywhere, unless `NODE_ENV=development` or `cookies: { secure: false }` is set.

## Related

- [Magic Link](../api/magic-link.md) — full handler reference, including the enumeration-safety,
  status-gating and MFA rules.
- [Bootstrap & Config](../api/bootstrap-config.md) — the `onMagicLinkRequested` hook shape.
- [Register, Login, Refresh, Logout example](register-login-refresh-logout.md) — magic-link login
  issues the same session/cookie shape as password login.
