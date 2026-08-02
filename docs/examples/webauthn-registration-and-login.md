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
- A logged-in user for registration (passkeys are added to an existing account).

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
  return verifyRes.json(); // 201 { id, credentialId, deviceType, backedUp, name }
}
```

## Log in with a passkey (no password)

```js
async function loginWithPasskey(email /* optional — omit for usernameless/discoverable login */) {
  const optRes = await fetch('/auth/webauthn/authentication/options', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(email ? { email } : {}),
  });
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
