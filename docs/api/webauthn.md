---
title: "WebAuthn / Passkeys"
package: "@okeav/idp-core"
category: "api-reference"
tags: ["auth", "webauthn", "passkeys"]
description: "Six ceremony endpoints across three flows — passkey registration, primary passwordless login, and passkey-as-MFA — plus listing and deleting a user's passkeys."
---

# WebAuthn / Passkeys

Six ceremony endpoints across three flows, plus two passkey-management endpoints, all opt-in
behind `config.webauthn.{rpID, rpName, origin}` — **validated lazily on first use, not at
`initIdentityProvider()` startup**, so consumers who don't use passkeys never need to configure
it.

```ts
webauthn?: {
  rpID?: string; rpName?: string; origin?: string | string[];
  allowCredentialsByEmail?: boolean; // default false — see "Primary passwordless login"
}
```

`rpID` must be the **frontend's** registrable domain — not necessarily this API's own hostname if
the API is deployed on a subdomain (e.g. API on `api.example.com` serving a frontend at
`example.com` → `rpID` is `example.com`, the common parent). Calling any WebAuthn handler before
`rpID`/`rpName`/`origin` are all set throws `WEBAUTHN_NOT_CONFIGURED` (500).

Built on `@simplewebauthn/server` (a direct dependency, requires Node ≥20).

## Flows

| Flow | Endpoints | Auth required? |
|---|---|---|
| Register a passkey on an existing account | `generateRegistrationOptionsHandler`, `verifyRegistrationHandler` | Yes, and a **recent login** (`requireRecentAuth()`) |
| List / delete your passkeys | `listPasskeysHandler`, `deletePasskeyHandler` | Yes (delete also needs a recent login) |
| Primary passwordless login | `generateAuthenticationOptionsHandler`, `verifyAuthenticationHandler` | No (rate limited per IP) |
| Passkey as an MFA second factor | `generateMfaWebauthnChallengeOptionsHandler`, `verifyMfaWebauthnChallengeHandler` | No (gated by a valid `mfaChallengeToken` instead) |

Registration always requires an authenticated caller — a passkey is added to an already-established
account (via password, magic link, SSO, ...). There is no "register a passkey for a brand-new
anonymous user" ceremony; combine a magic-link signup with an immediate registration call if you
want that UX (the magic-link login is itself recent).

**Step-up for registration and deletion.** A passkey is a login of its own that survives
logout-all and password reset, so a stolen session must not be able to add one. `buildRouter()`
mounts `requireRecentAuth()` in front of both registration endpoints and
`DELETE /me/passkeys/:credentialId`: unless the access token's `auth_time` is within
`config.session.recentAuthMaxAgeSeconds` (default 900 s), they answer 401
`REAUTHENTICATION_REQUIRED` — send the user through a login (a token refresh doesn't count) and
retry. Wiring the handlers yourself, mount it the same way:

```js
router.post('/webauthn/registration/options', authContextMiddleware(), requireRecentAuth(),
    validateBody(schemas.registrationOptionsSchema), generateRegistrationOptionsHandler);
router.post('/webauthn/registration/verify', authContextMiddleware(), requireRecentAuth(),
    validateBody(schemas.verifyRegistrationSchema), verifyRegistrationHandler);
router.get('/me/passkeys', authContextMiddleware(), listPasskeysHandler);
router.delete('/me/passkeys/:credentialId', authContextMiddleware(), requireRecentAuth(), deletePasskeyHandler);
```

**User verification (UV).** Registration and primary login *require* UV (a PIN or biometric) —
explicitly, not by library default: a passkey that logs in on its own must verify its user. An
assertion or attestation without the UV flag is refused (`WEBAUTHN_VERIFICATION_FAILED`).
Passkey-as-MFA explicitly does *not* require it (the password was the knowledge factor), so a
PIN-less security key works as a second factor.

**Single-use challenges.** Challenges are redeemed with the cache's atomic `take()` (get-and-delete;
`MULTI` GET+DEL on Redis), so two concurrent verifies can never both redeem one challenge. The
credential's signature counter is written only if it advanced
(`credentialRepository.updateCounter` resolves whether it did), so a cloned authenticator's
assertion can't be used twice concurrently either — a counter that didn't advance answers
`WEBAUTHN_VERIFICATION_FAILED`.

Credentials are stored via a `CredentialRepository` — see [Repository Adapters](repository-adapters.md).
A custom cache adapter must implement `take()` — see [Cache Interface](cache-interface.md).

## Registration

**`POST /webauthn/registration/options`** (auth + recent login required)

Body: `{}` (no fields). Generates registration options via `@simplewebauthn/server`, excluding the
user's already-registered credentials (`excludeCredentials`), with
`authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' }` and
`attestationType: 'none'`. Stores the challenge keyed by `reg:<userId>` in the cache
(`config.ttls.webauthnChallenge`, default 300s).

**Errors**: `UNAUTHENTICATED` (401, no `req.auth.userId`); `REAUTHENTICATION_REQUIRED` (401);
`USER_NOT_FOUND` (404, token's user no longer exists).

**`POST /webauthn/registration/verify`** (auth + recent login required)

Body: `{ response: <RegistrationResponseJSON>, name?: string (max 120) }`.

Verifies against the stored challenge (consumed atomically) with user verification required,
then persists `{ userId, credentialId, publicKey (base64),
counter, transports, deviceType, backedUp, name }` via `credentialRepository.create()`.

**Success (201)**: `{ id, credentialId, deviceType, backedUp, name }`.

**Errors**: `UNAUTHENTICATED` (401, no `req.auth.userId`); `REAUTHENTICATION_REQUIRED` (401);
`WEBAUTHN_CHALLENGE_EXPIRED` (400, no matching stored challenge — restart registration);
`WEBAUTHN_VERIFICATION_FAILED` (400, `@simplewebauthn/server` rejected the response or threw). This
handler never looks up the user record, so it cannot throw `USER_NOT_FOUND` — that only comes from
`/registration/options` above.

Audit event: `WEBAUTHN_CREDENTIAL_REGISTERED` (`{ userId, credentialId }`).

## Managing passkeys

**`GET /me/passkeys`** — `listPasskeysHandler` (auth required)

→ `[{ credentialId, name, deviceType, backedUp, createdAt, lastUsedAt }]` — the caller's own
passkeys. Public keys and signature counters are never returned. `name`, `createdAt` and
`lastUsedAt` are `null` when the adapter has none.

**`DELETE /me/passkeys/:credentialId`** — `deletePasskeyHandler` (auth + recent login required)

Removes one of the caller's passkeys — lets a user evict a passkey they don't recognise. Scoped to
the caller: someone else's (or an unknown) credential id answers 404 `CREDENTIAL_NOT_FOUND`.
→ `{ status: 'ok' }`. Audit event: `WEBAUTHN_CREDENTIAL_DELETED` (`{ userId, credentialId }`).

**Errors**: `UNAUTHENTICATED` (401); `REAUTHENTICATION_REQUIRED` (401, delete only);
`CREDENTIAL_NOT_FOUND` (404).

## Primary passwordless login

Both endpoints are rate limited per IP, fail-closed, against `config.rateLimiting.webauthnAuthentication`
(default 60 requests per 5 minutes — a login is two requests; key `webauthn-authn:ip:<ip>`):
429 `RATE_LIMIT_EXCEEDED`, or 503 `RATE_LIMITER_UNAVAILABLE` if the limiter backend errors. The
limit also bounds how many challenges one IP can park in the cache.

**`POST /webauthn/authentication/options`** (no auth)

Body: `{ email?: string }`. By default `email` is **ignored** and the response is always a
usernameless/discoverable-credential challenge (the browser lets the user pick which passkey to
use): listing an address's credential ids would tell anyone who asks whether it has an account
with passkeys. Options always ask for `userVerification: 'required'`.

Set `config.webauthn.allowCredentialsByEmail: true` only if you rely on non-discoverable
credentials. `email` then scopes `allowCredentials` to that account's credential ids (with no
`transports` listed, which would tell real credentials from the decoy), and an address with no
account or no passkeys gets a **stable decoy id** (an HMAC of the address), so it looks like an
account with one passkey.

Challenge is stored keyed by the challenge value itself (`authn:<challenge>`), not a userId —
there's no natural "known user" key for a usernameless ceremony.

**`POST /webauthn/authentication/verify`** (no auth)

Body: `{ response: <AuthenticationResponseJSON>, login_challenge?: string }` (`login_challenge`: see [Login challenges](oauth2-authorization-server.md#login-challenges) — the new session is bound to it). Decodes the challenge back out of
`response.response.clientDataJSON`, consumes the stored challenge (atomically), verifies the
assertion against the stored credential (looked up by `response.id`) with user verification
required, advances the credential's signature counter (conditional write — replay protection),
checks that a discoverable assertion's `userHandle` names the credential's owner, loads the owning
user, and issues a full session through the same `resolveAuthContext` → `issueSession` path as
every other login method. A passkey login is not followed by a TOTP challenge — a
user-verifying passkey is already two factors. Because it sets session cookies, every browser
request is subject to the [CSRF origin check](middleware.md#csrf-origin-check) (403
`CSRF_ORIGIN_REJECTED` from an origin that is neither the issuer's nor in
`cookies.trustedOrigins`). A failed-password lockout doesn't block passkey login (it locks password
login only); a passkey login doesn't lift it either (only a lock recorded before 0.4.0 is cleared).

**Success (200)**: `{ accessToken, accessTokenExpiresAt, refreshToken, refreshTokenExpiresAt, userId }`
+ session cookies set (`refreshToken` is in the body only as
[`cookies.refreshTokenInBody`](bootstrap-config.md#cookiesrefreshtokeninbody) allows — by default,
only for non-browser clients).

**Errors**: `RATE_LIMIT_EXCEEDED` (429) / `RATE_LIMITER_UNAVAILABLE` (503); `INVALID_REQUEST`
(400, malformed assertion — can't decode challenge or missing `response.id`);
`WEBAUTHN_CHALLENGE_EXPIRED` (400); `CREDENTIAL_NOT_FOUND` (400, unknown credential ID);
`WEBAUTHN_VERIFICATION_FAILED` (400 — verification failed, no UV, counter didn't advance, or
`userHandle` doesn't match the owner); `USER_NOT_FOUND` (404); `CSRF_ORIGIN_REJECTED` (403);
whatever `assertUsableStatus` throws for a non-`ACTIVE` user (`ACCOUNT_LOCKED` 423 only for an
administrative lock).

## Passkey as MFA second factor

Alternative to `verifyMfaChallengeHandler` (TOTP) for completing the MFA gate `loginHandler` puts
up when `user.mfaEnabled`. Unlike primary login, the user is already partially identified (a
`mfaChallengeToken` proves the password step passed) — so the server independently confirms the
submitted credential actually belongs to *that* user, not just that it's some valid registered
passkey (defense in depth beyond `allowCredentials` scoping in the browser).

**`POST /webauthn/mfa/options`**

Body: `{ mfaChallengeToken: string }`. Verifies the challenge token (it isn't spent here), loads that user's credentials
(`CREDENTIAL_NOT_FOUND` 400 if none registered), generates options with
`userVerification: 'discouraged'` (not `'preferred'`/`'required'` — the password step already
established presence/verification; re-demanding it here just adds friction, per
`@simplewebauthn`'s own guidance for a 2FA step). Challenge stored keyed by `mfa-webauthn:<userId>`.

**`POST /webauthn/mfa/verify`**

Body: `{ mfaChallengeToken: string, response: <AuthenticationResponseJSON> }`. Subject to the
[CSRF origin check](middleware.md#csrf-origin-check) for every browser request (it sets session
cookies). Rate limited,
fail-closed, on the same `mfa-challenge:ip:<req.ip>` key and `config.rateLimiting.mfaChallenge`
rule as TOTP's `/mfa/verify`. Re-verifies the challenge token (refusing one issued before the
account's last password change), then — under the [per-account MFA
lockout](mfa.md#per-account-lockout) shared with TOTP and recovery codes (`method: 'webauthn'`,
counted before the assertion is checked) — consumes the stored challenge, verifies the assertion
(user verification **not** required, matching the options' `'discouraged'`), and explicitly
checks `credentialDoc.user === userId` from the challenge token (not merely "is this a valid
registered credential"). Only then is the challenge token spent (one token, one login) and a
session issued. Every attempt takes a slot in the lockout budget; a failed, malformed, or
unknown-credential assertion is a wrong guess (and can trigger `MFA_LOCKED`), while one that fails
for another reason — e.g. an expired challenge — still keeps its slot.

**Success (200)**: same shape as primary WebAuthn login.

**Errors**: `INVALID_MFA_CHALLENGE_TOKEN` (401, invalid/expired/already-used token, or issued
before the last password change); `CREDENTIAL_NOT_FOUND`
(400, no passkeys registered); `WEBAUTHN_CHALLENGE_EXPIRED` (400);
`WEBAUTHN_VERIFICATION_FAILED` (401, credential belongs to a different user than the challenge —
distinct 401 from the 400 used for a straightforward crypto-verification failure);
`USER_NOT_ACTIVE` (403 — not for a failed-password lockout, only an inactive or administratively
locked account); `CSRF_ORIGIN_REJECTED` (403); `MFA_LOCKED` (429); `RATE_LIMIT_EXCEEDED` (429) /
`RATE_LIMITER_UNAVAILABLE` (503).

## Related

- [Repository Adapters](repository-adapters.md) — `CredentialRepository` shape.
- [Cache Interface](cache-interface.md) — challenge storage (`take()`).
- [Middleware](middleware.md) — `requireRecentAuth()`.
- [Password & Email Auth](password-email-auth.md) — the shared `issueSession` mechanics.
- [MFA](mfa.md) — the TOTP alternative to passkey-as-MFA.
- [WebAuthn Registration & Login example](../examples/webauthn-registration-and-login.md)
