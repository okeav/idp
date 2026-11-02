---
title: "WebAuthn: Register a Passkey and Log In With It"
package: "@okeav/idp-core"
category: "example"
tags: ["auth", "webauthn", "passkeys"]
description: "Browser-side navigator.credentials glue plus the two server round trips for passkey registration and passwordless login."
---

# WebAuthn: Register a Passkey and Log In With It

WebAuthn response objects (`ArrayBuffer`s, etc.) don't serialize to JSON directly — the browser
side needs small base64url conversion helpers. This example is adapted from the package's own
`examples/e2e-test-harness/public/webauthn-client.js`.

## Prerequisites

- A running idp-core server with `config.webauthn` configured:
  ```js
  webauthn: { rpID: 'localhost', rpName: 'My App', origin: 'http://localhost:3000' }
  ```
  `rpID` must be your **frontend's** registrable domain — see [WebAuthn](../api/webauthn.md).
- A browser (WebAuthn requires `navigator.credentials`, unavailable in plain Node).
- A logged-in user for registration (passkeys are added to an existing account) who logged in
  **recently** — within `session.recentAuthMaxAgeSeconds` (default 15 minutes). A session kept
  alive only by refreshing doesn't count.
- An authenticator that can verify its user (PIN, biometric): registration and passkey login
  require user verification.

## Browser-side helpers

```js
// base64url <-> ArrayBuffer glue — exactly what @simplewebauthn/browser does internally.
function b64urlToBuffer(b64url) {
  const pad = b64url + '='.repeat((4 - (b64url.length % 4)) % 4);
  const bin = atob(pad.replace(/-/g, '+').replace(/_/g, '/'));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0)).buffer;
}
function bufferToB64url(buf) {
  const bin = String.fromCharCode(...new Uint8Array(buf));
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
```

## Register a passkey (authenticated user)

```js
async function registerPasskey(accessToken, name) {
  // 1. Get options from the server.
  const optRes = await fetch('/auth/webauthn/registration/options', {
    method: 'POST',
    headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
    body: '{}',
  });
  // 401 REAUTHENTICATION_REQUIRED: the login is too old — sign the user in again, then retry.
  if (!optRes.ok) throw await optRes.json();
  const options = await optRes.json();

  // 2. Convert to the shape navigator.credentials.create() expects.
  const publicKey = {
    ...options,
    challenge: b64urlToBuffer(options.challenge),
    user: { ...options.user, id: b64urlToBuffer(options.user.id) },
    excludeCredentials: (options.excludeCredentials || []).map((c) => ({ ...c, id: b64urlToBuffer(c.id) })),
  };

  // 3. Prompt the platform authenticator (Touch ID, Windows Hello, a security key, ...).
  const cred = await navigator.credentials.create({ publicKey });

  // 4. Serialize the credential response back to JSON and verify server-side.
  const response = {
    id: cred.id,
    rawId: bufferToB64url(cred.rawId),
    type: cred.type,
    clientExtensionResults: cred.getClientExtensionResults(),
    response: {
      clientDataJSON: bufferToB64url(cred.response.clientDataJSON),
      attestationObject: bufferToB64url(cred.response.attestationObject),
      transports: cred.response.getTransports?.() || [],
    },
  };

  const verifyRes = await fetch('/auth/webauthn/registration/verify', {
    method: 'POST',
    headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ response, name }),
  });
  if (!verifyRes.ok) throw await verifyRes.json();
  return verifyRes.json(); // 201 { id, credentialId, deviceType, backedUp, name }
}
```

## List and remove passkeys

```js
async function listPasskeys(accessToken) {
  const res = await fetch('/auth/me/passkeys', { headers: { Authorization: `Bearer ${accessToken}` } });
  return res.json(); // [{ credentialId, name, deviceType, backedUp, createdAt, lastUsedAt }]
}

async function removePasskey(accessToken, credentialId) {
  const res = await fetch(`/auth/me/passkeys/${encodeURIComponent(credentialId)}`, {
    method: 'DELETE',
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  // REAUTHENTICATION_REQUIRED (401) as for registration; CREDENTIAL_NOT_FOUND (404) if it isn't yours
  if (!res.ok) throw await res.json();
  return res.json(); // { status: 'ok' }
}
```

A passkey survives logout-all and password reset, so give users this list somewhere in their
security settings — it's how they evict a passkey they don't recognise.

## Log in with a passkey (no password)

```js
async function loginWithPasskey() {
  // Usernameless/discoverable login: the browser lets the user pick a passkey. (An `email` in the
  // body is ignored unless the server sets webauthn.allowCredentialsByEmail: true.)
  const optRes = await fetch('/auth/webauthn/authentication/options', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: '{}',
  });
  if (!optRes.ok) throw await optRes.json(); // RATE_LIMIT_EXCEEDED (429) per IP
  const options = await optRes.json();

  const publicKey = {
    ...options,
    challenge: b64urlToBuffer(options.challenge),
    allowCredentials: (options.allowCredentials || []).map((c) => ({ ...c, id: b64urlToBuffer(c.id) })),
  };

  const cred = await navigator.credentials.get({ publicKey });

  const response = {
    id: cred.id,
    rawId: bufferToB64url(cred.rawId),
    type: cred.type,
    clientExtensionResults: cred.getClientExtensionResults(),
    response: {
      clientDataJSON: bufferToB64url(cred.response.clientDataJSON),
      authenticatorData: bufferToB64url(cred.response.authenticatorData),
      signature: bufferToB64url(cred.response.signature),
      userHandle: cred.response.userHandle ? bufferToB64url(cred.response.userHandle) : undefined,
    },
  };

  const verifyRes = await fetch('/auth/webauthn/authentication/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ response }),
    credentials: 'include', // accept the session cookies
  });
  if (!verifyRes.ok) throw await verifyRes.json();
  return verifyRes.json(); // { accessToken, accessTokenExpiresAt, refreshToken, refreshTokenExpiresAt, userId }
}
```

Both calls count toward a per-IP limit (`rateLimiting.webauthnAuthentication`, 60 per 5 minutes
by default).

## Passkey as an MFA second factor

Same browser-side flow, but scoped to a specific pending login via `mfaChallengeToken` instead of
`email`, and posted to `/auth/webauthn/mfa/options` / `/auth/webauthn/mfa/verify` — see
[WebAuthn](../api/webauthn.md#passkey-as-mfa-second-factor) for the request-shape differences.

## Related

- [WebAuthn](../api/webauthn.md) — full handler reference for all three flows.
- [Repository Adapters](../api/repository-adapters.md) — `CredentialRepository`.
- [Cache Interface](../api/cache-interface.md) — challenge storage (challenges expire after
  `config.ttls.webauthnChallenge`, default 5 minutes — restart the ceremony if you see
  `WEBAUTHN_CHALLENGE_EXPIRED`).
