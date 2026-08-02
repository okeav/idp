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
import { initIdentityProvider, buildRouter, cookieParser } from '@okeav/idp-core';

await initIdentityProvider({
  issuer: 'http://localhost:3000',
  mongo: { uri: 'mongodb://localhost:27017/idp?replicaSet=rs0' },
  signingKeys: { keys: { 'k1': { privateKey, publicKey, status: 'ACTIVE' } } },
  security: { emailHashPepper: '...', tokenHashSecret: '...' },

  // Invite-only apps: set false so an unrecognized email silently no-ops
  // instead of creating a new account via magic link.
  magicLink: { allowSignupViaMagicLink: true },

  hooks: {
    onMagicLinkRequested: async ({ email, magicLinkToken, isNewUser }) => {
      const url = `https://app.example.com/magic-link/verify?token=${magicLinkToken}`;
      await sendEmail(email, isNewUser
        ? `Welcome! Click to finish signing up: ${url}`
        : `Click to log in: ${url}`);
    },
    resolveAuthContext: async () => ({ claims: { role: 'member' } }),
  },
});
```

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

This is rate-limited to 3 requests per hour per IP by default
(`config.rateLimiting.magicLink` — see [Rate Limiter Interface](../api/rate-limiter-interface.md)).

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
    // err.error === 'INVALID_OR_EXPIRED_TOKEN' if the link was already used or expired
    // (the link is single-use — a second click always fails).
    throw err;
  }
  return res.json(); // { accessToken, accessTokenExpiresAt, refreshToken, refreshTokenExpiresAt, userId, isNewUser }
}
```

`isNewUser: true` in the response tells your frontend this was a first-time signup via magic
link — useful for routing to an onboarding flow vs. a normal post-login redirect.

## Related

- [Magic Link](../api/magic-link.md) — full handler reference, including the enumeration-safety
  and status-gating rules.
- [Bootstrap & Config](../api/bootstrap-config.md) — the `onMagicLinkRequested` hook shape.
- [Register, Login, Refresh, Logout example](register-login-refresh-logout.md) — magic-link login
  issues the same session/cookie shape as password login.
