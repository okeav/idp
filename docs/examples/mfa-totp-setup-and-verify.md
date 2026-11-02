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

Setup and confirm require a **recent login** — by default, within the last 15 minutes
(`session.recentAuthMaxAgeSeconds`). A session kept alive by refreshing doesn't count: if either
call answers `401 { error: 'REAUTHENTICATION_REQUIRED' }`, send the user through a login and retry
with the new access token.

```js
const BASE = 'http://localhost:3000/auth';
const authHeader = (token) => ({ Authorization: `Bearer ${token}` });

// 1. Start setup — generates a secret, not yet active.
async function startMfaSetup(accessToken) {
  const res = await fetch(`${BASE}/me/mfa/setup`, { method: 'POST', headers: authHeader(accessToken) });
  if (!res.ok) throw await res.json(); // REAUTHENTICATION_REQUIRED (401) if the login isn't recent
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

Confirming signs the account out of **every other session** (other devices, other browsers); the
session that confirmed stays signed in. The code used to confirm is spent — the user can't log in
with that same code, and has to wait for their app's next one.

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
  // (expiresIn is a duration in seconds, default 300 — see mfa.md). Magic-link verify answers
  // the same way; SSO puts the same fields in the redirect's URL fragment.
}

async function completeMfaLogin(mfaChallengeToken, code) {
  const res = await fetch(`${BASE}/mfa/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ mfaChallengeToken, code }),
    credentials: 'include',
  });
  if (!res.ok) throw await res.json(); // INVALID_MFA_CODE, INVALID_MFA_CHALLENGE_TOKEN (expired or already used), or MFA_LOCKED
  return res.json(); // same shape as a normal login success
}

// `code` here can be either the current TOTP code OR one of the recovery
// codes issued at setup (`XXXXX-XXXXX-XXXXX-XXXXX`; any case, spaces and dashes optional,
// O/I/L read as 0/1) —
// verifyMfaChallengeHandler tries TOTP first, then falls back to recovery codes
// automatically (see mfa.md).
```

Each piece is single-use: a TOTP code is accepted once (a second login in the same 30-second
window needs the next code), a recovery code is spent when used, and a `mfaChallengeToken`
completes one login only — after a success, or once it expires, start again from `/login`.

**Lockout**: 5 wrong codes within 15 minutes (TOTP, recovery code, or passkey-as-MFA combined, by
default) lock the account's second-factor step for 15 minutes. While locked, every attempt —
even a correct code — gets `429 { error: 'MFA_LOCKED' }`, so show a "try again later" message
rather than "wrong code". Wrong MFA codes don't count toward the *password* lockout. See
[MFA](../api/mfa.md#per-account-lockout).

## Disable MFA / regenerate recovery codes

Both need the account's password **and** a current TOTP code. An account without a password
(signed up through SSO or a magic link) sends only `code`.

```js
async function disableMfa(accessToken, password, code) {
  const res = await fetch(`${BASE}/me/mfa`, {
    method: 'DELETE',
    headers: { ...authHeader(accessToken), 'Content-Type': 'application/json' },
    // Counted against the MFA lockout first, then password, then the TOTP code.
    body: JSON.stringify(password ? { password, code } : { code }),
  });
  if (!res.ok) throw await res.json(); // CURRENT_PASSWORD_INCORRECT, INVALID_MFA_CODE, MFA_LOCKED
  return res.json(); // { mfaEnabled: false } — also discards all recovery codes
}

async function regenerateRecoveryCodes(accessToken, password, code) {
  const res = await fetch(`${BASE}/me/mfa/recovery-codes`, {
    method: 'POST',
    headers: { ...authHeader(accessToken), 'Content-Type': 'application/json' },
    body: JSON.stringify(password ? { password, code } : { code }), // a TOTP code is required (since 0.4.0)
  });
  if (!res.ok) throw await res.json(); // CURRENT_PASSWORD_INCORRECT, INVALID_MFA_CODE, MFA_LOCKED
  return res.json(); // { recoveryCodes: [...] } — old codes are now invalid
}
```

## Related

- [MFA](../api/mfa.md) — full handler reference, including the recovery-code fallback order, the
  per-account lockout, and the server-side `mfa.encryptionKey` this flow needs.
- [WebAuthn](../api/webauthn.md) — passkey-as-MFA is an alternative second factor that consumes
  the same `mfaChallengeToken`.
- [Password & Email Auth](../api/password-email-auth.md) — the `mfaRequired` branch of `loginHandler`.
