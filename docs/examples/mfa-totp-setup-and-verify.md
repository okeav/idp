---
title: "MFA (TOTP) Setup and Login Verification"
package: "@okeav/idp-core"
category: "example"
tags: ["auth", "mfa", "totp"]
description: "Enable TOTP MFA on an account, save recovery codes, then complete a login that requires the second factor."
---

# MFA (TOTP) Setup and Login Verification

Enabling and using time-based one-time-password (TOTP) two-factor auth (e.g. Google Authenticator,
1Password, Authy).

## Prerequisites

- A running idp-core server, with a logged-in user (see
  [Register, Login, Refresh, Logout](register-login-refresh-logout.md)), configured with
  `mfa.encryptionKey` (32 bytes, base64 — `openssl rand -base64 32`) so TOTP secrets are encrypted
  at rest. The server won't start without one unless `mfa.enabled: false` (see [MFA](../api/mfa.md#secret-encryption-at-rest)).
- A QR-code rendering library on your frontend — this package returns the raw `otpauth://` URI
  and does **not** render a QR code itself (see [MFA](../api/mfa.md)).

## Enable MFA

```js
const BASE = 'http://localhost:3000/auth';
const authHeader = (token) => ({ Authorization: `Bearer ${token}` });

// 1. Start setup — generates a secret, not yet active.
async function startMfaSetup(accessToken) {
  const res = await fetch(`${BASE}/me/mfa/setup`, { method: 'POST', headers: authHeader(accessToken) });
  return res.json(); // { secret, otpauthUrl } — render otpauthUrl as a QR code client-side
}

// 2. User scans the QR code, then submits the 6-digit code their app shows.
async function confirmMfaSetup(accessToken, code) {
  const res = await fetch(`${BASE}/me/mfa/confirm`, {
    method: 'POST',
    headers: { ...authHeader(accessToken), 'Content-Type': 'application/json' },
    body: JSON.stringify({ code }),
  });
  if (!res.ok) throw await res.json(); // INVALID_MFA_CODE if the code doesn't verify; MFA_LOCKED (429) after too many
  return res.json(); // { mfaEnabled: true, recoveryCodes: [...] } — shown ONCE, prompt the user to save them
}
```

`recoveryCodes` are returned in plaintext exactly once, at confirmation time (and again if you
call `/me/mfa/recovery-codes` to regenerate). There's no way to retrieve the same set again — if
the user loses them, regenerate a fresh set.

## Complete a login that requires MFA

```js
async function login(email, password) {
  const res = await fetch(`${BASE}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  });
  return res.json();
  // If the account has MFA enabled: { mfaRequired: true, mfaChallengeToken, expiresIn }
  // (expiresIn is a duration in seconds, default 300 — see mfa.md)
}

async function completeMfaLogin(mfaChallengeToken, code) {
  const res = await fetch(`${BASE}/mfa/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ mfaChallengeToken, code }),
    credentials: 'include',
  });
  if (!res.ok) throw await res.json(); // INVALID_MFA_CODE, INVALID_MFA_CHALLENGE_TOKEN if expired, or MFA_LOCKED
  return res.json(); // same shape as a normal login success
}

// `code` here can be either the current TOTP code OR one of the recovery
// codes issued at setup (`XXXXXX-XXXXXX`) — verifyMfaChallengeHandler tries
// TOTP first, then falls back to recovery codes automatically (see mfa.md).
```

**Lockout**: 5 wrong codes within 15 minutes (TOTP, recovery code, or passkey-as-MFA combined, by
default) lock the account's second-factor step for 15 minutes. While locked, every attempt —
even a correct code — gets `429 { error: 'MFA_LOCKED' }`, so show a "try again later" message
rather than "wrong code". See [MFA](../api/mfa.md#per-account-lockout).

## Disable MFA / regenerate recovery codes

```js
async function disableMfa(accessToken, password, code) {
  const res = await fetch(`${BASE}/me/mfa`, {
    method: 'DELETE',
    headers: { ...authHeader(accessToken), 'Content-Type': 'application/json' },
    body: JSON.stringify({ password, code }), // lockout checked first, then password, then the TOTP code
  });
  return res.json(); // { mfaEnabled: false } — also discards all recovery codes
}

async function regenerateRecoveryCodes(accessToken, password) {
  const res = await fetch(`${BASE}/me/mfa/recovery-codes`, {
    method: 'POST',
    headers: { ...authHeader(accessToken), 'Content-Type': 'application/json' },
    body: JSON.stringify({ password }), // no TOTP code needed for this one
  });
  return res.json(); // { recoveryCodes: [...] } — old codes are now invalid
}
```

## Related

- [MFA](../api/mfa.md) — full handler reference, including the recovery-code fallback order, the
  per-account lockout, and the server-side `mfa.encryptionKey` this flow needs.
- [WebAuthn](../api/webauthn.md) — passkey-as-MFA is an alternative second factor that consumes
  the same `mfaChallengeToken`.
- [Password & Email Auth](../api/password-email-auth.md) — the `mfaRequired` branch of `loginHandler`.
