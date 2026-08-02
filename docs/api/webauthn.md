---
title: "WebAuthn / Passkeys"
package: "@okeav/idp-core"
category: "api-reference"
tags: ["auth", "webauthn", "passkeys"]
description: "Six ceremony endpoints across three flows: passkey registration, primary passwordless login, and passkey-as-MFA."
---

# WebAuthn / Passkeys

Six ceremony endpoints across three flows, all opt-in behind `config.webauthn.{rpID, rpName,
origin}` — **validated lazily on first use, not at `initIdentityProvider()` startup**, so
consumers who don't use passkeys never need to configure it.

```ts
webauthn?: { rpID?: string; rpName?: string; origin?: string | string[] }
```

`rpID` must be the **frontend's** registrable domain — not necessarily this API's own hostname if
the API is deployed on a subdomain (e.g. API on `api.example.com` serving a frontend at
`example.com` → `rpID` is `example.com`, the common parent). Calling any WebAuthn handler before
`rpID`/`rpName`/`origin` are all set throws `WEBAUTHN_NOT_CONFIGURED` (500).

Built on `@simplewebauthn/server` (a direct dependency, requires Node ≥20).

## Flows

| Flow | Endpoints | Auth required? |
|---|---|---|
| Register a passkey on an existing account | `generateRegistrationOptionsHandler`, `verifyRegistrationHandler` | Yes |
| Primary passwordless login | `generateAuthenticationOptionsHandler`, `verifyAuthenticationHandler` | No |
| Passkey as an MFA second factor | `generateMfaWebauthnChallengeOptionsHandler`, `verifyMfaWebauthnChallengeHandler` | No (gated by a valid `mfaChallengeToken` instead) |

Registration always requires an authenticated caller — a passkey is added to an already-established
account (via password, magic link, SSO, ...). There is no "register a passkey for a brand-new
anonymous user" ceremony; combine a magic-link signup with an immediate registration call if you
want that UX.

Credentials are stored via a `CredentialRepository` — see [Repository Adapters](repository-adapters.md).

## Registration

**`POST /webauthn/registration/options`** (auth required)

Body: `{}` (no fields). Generates registration options via `@simplewebauthn/server`, excluding the
user's already-registered credentials (`excludeCredentials`), with
`authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' }` and
`attestationType: 'none'`. Stores the challenge keyed by `reg:<userId>` in the cache
(`config.ttls.webauthnChallenge`, default 300s).

**Errors**: `UNAUTHENTICATED` (401, no `req.auth.userId`); `USER_NOT_FOUND` (404, token's user no
longer exists).

**`POST /webauthn/registration/verify`** (auth required)

Body: `{ response: <RegistrationResponseJSON>, name?: string (max 120) }`.

Verifies against the stored challenge, then persists `{ userId, credentialId, publicKey (base64),
counter, transports, deviceType, backedUp, name }` via `credentialRepository.create()`.

**Success (201)**: `{ id, credentialId, deviceType, backedUp, name }`.

**Errors**: `UNAUTHENTICATED` (401, no `req.auth.userId`);
`WEBAUTHN_CHALLENGE_EXPIRED` (400, no matching stored challenge — restart registration);
`WEBAUTHN_VERIFICATION_FAILED` (400, `@simplewebauthn/server` rejected the response or threw). This
handler never looks up the user record, so it cannot throw `USER_NOT_FOUND` — that only comes from
`/registration/options` above.

## Primary passwordless login

**`POST /webauthn/authentication/options`** (no auth)

Body: `{ email?: string }` — `email` is **optional**. Omit it for a usernameless/discoverable-
credential challenge (the browser lets the user pick which passkey to use). If provided, scopes
`allowCredentials` to that user's registered credentials — but an **unknown email still gets a
real (if uncompletable) challenge** rather than a distinguishable error (enumeration-safe).
Challenge is stored keyed by the challenge value itself (`authn:<challenge>`), not a userId —
there's no natural "known user" key for a usernameless ceremony.

**`POST /webauthn/authentication/verify`** (no auth)

Body: `{ response: <AuthenticationResponseJSON> }`. Decodes the challenge back out of
`response.response.clientDataJSON`, consumes the stored challenge, verifies the assertion against
the stored credential (looked up by `response.id`), updates the credential's signature counter
(replay protection), loads the owning user, and issues a full session through the same
`resolveAuthContext` → `issueSession` path as every other login method.

**Success (200)**: `{ accessToken, accessTokenExpiresAt, refreshToken, refreshTokenExpiresAt, userId }`
+ session cookies set.

**Errors**: `INVALID_REQUEST` (400, malformed assertion — can't decode challenge or missing
`response.id`); `WEBAUTHN_CHALLENGE_EXPIRED` (400); `CREDENTIAL_NOT_FOUND` (400, unknown
credential ID); `WEBAUTHN_VERIFICATION_FAILED` (400); `USER_NOT_FOUND` (404); whatever
`assertUsableStatus` throws for a non-`ACTIVE` user.

## Passkey as MFA second factor

Alternative to `verifyMfaChallengeHandler` (TOTP) for completing the MFA gate `loginHandler` puts
up when `user.mfaEnabled`. Unlike primary login, the user is already partially identified (a
`mfaChallengeToken` proves the password step passed) — so the server independently confirms the
submitted credential actually belongs to *that* user, not just that it's some valid registered
passkey (defense in depth beyond `allowCredentials` scoping in the browser).

**`POST /webauthn/mfa/options`**

Body: `{ mfaChallengeToken: string }`. Verifies the challenge token, loads that user's credentials
(`CREDENTIAL_NOT_FOUND` 400 if none registered), generates options with
`userVerification: 'discouraged'` (not `'preferred'`/`'required'` — the password step already
established presence/verification; re-demanding it here just adds friction, per
`@simplewebauthn`'s own guidance for a 2FA step). Challenge stored keyed by `mfa-webauthn:<userId>`.

**`POST /webauthn/mfa/verify`**

Body: `{ mfaChallengeToken: string, response: <AuthenticationResponseJSON> }`. Re-verifies the
challenge token, consumes the stored challenge, verifies the assertion, then explicitly checks
`credentialDoc.user === userId` from the challenge token (not merely "is this a valid registered
credential") before issuing a session.

**Success (200)**: same shape as primary WebAuthn login.

**Errors**: `INVALID_MFA_CHALLENGE_TOKEN` (401, invalid/expired token); `CREDENTIAL_NOT_FOUND`
(400, no passkeys registered); `WEBAUTHN_CHALLENGE_EXPIRED` (400);
`WEBAUTHN_VERIFICATION_FAILED` (401, credential belongs to a different user than the challenge —
distinct 401 from the 400 used for a straightforward crypto-verification failure);
`USER_NOT_ACTIVE` (403).

## Related

- [Repository Adapters](repository-adapters.md) — `CredentialRepository` shape.
- [Cache Interface](cache-interface.md) — challenge storage.
- [Password & Email Auth](password-email-auth.md) — the shared `issueSession` mechanics.
- [MFA](mfa.md) — the TOTP alternative to passkey-as-MFA.
- [WebAuthn Registration & Login example](../examples/webauthn-registration-and-login.md)
