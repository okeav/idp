---
title: "Error Handling"
package: "@okeav/idp-core"
category: "api-reference"
tags: ["errors", "error-handling"]
description: "The IdpError type, isIdpError(), idpErrorHandler(), and the full ERROR_CODES catalogue with HTTP statuses."
---

# Error Handling

Every error this package's handlers throw on purpose is an `IdpError`, passed to `next(err)`. The
package never shapes an HTTP response body itself — mount one Express error-handling middleware
after the router. The exported `idpErrorHandler()` is safe to expose to the internet:

```js
import { buildRouter, idpErrorHandler } from '@okeav/idp-core';

app.use('/auth', buildRouter());
app.use(idpErrorHandler({ logger })); // after the router; logger is optional (default: the one given to initIdentityProvider)
```

**Don't echo `err.message` for every error.** Errors that aren't `IdpError`s (a database driver
error, a body-parser error, a bug) carry internal detail — collection and index names, values, the
raw request body — and an `IdpError` of 500+ may wrap one in `cause`. The hand-written handler this
page showed before 0.4.0 did exactly that. If you write your own handler for a different envelope,
keep the rule: show `message` only for an `IdpError` with `httpStatus < 500` (`err.expose === true`),
and answer everything else with a generic 500.

## `idpErrorHandler(opts?)`

```ts
function idpErrorHandler(opts?: { logger?: Logger }): ErrorRequestHandler
```

| Error | Response |
|---|---|
| `IdpError` with `httpStatus < 500` | `httpStatus`, `{ error: code, message }` |
| Body-parser "too large" (`type: 'entity.too.large'`, or status 413) | 413 `{ error: 'PAYLOAD_TOO_LARGE', message: 'Request body is too large' }` |
| Body-parser malformed body (`type: 'entity.parse.failed'`) | 400 `{ error: 'INVALID_REQUEST', message: 'Malformed request body' }` |
| `IdpError` with `httpStatus >= 500` | `httpStatus`, `{ error: code }` — no message; logged with `logger.error` |
| Anything else | 500 `{ error: 'INTERNAL_ERROR' }` — no message, stack or driver detail; logged with `logger.error` |

If the response headers were already sent, it just ends the response.

## `IdpError`

```ts
class IdpError extends Error {
  code: string;
  httpStatus: number;  // default 500
  status: number;      // mirrors httpStatus
  statusCode: number;  // mirrors httpStatus
  expose: boolean;     // httpStatus < 500 — the message is written for clients
  cause?: unknown;
  constructor(opts: { code: string; httpStatus?: number; message?: string; cause?: unknown });
}
```

`name` is always `'IdpError'`. `code` defaults to `'INTERNAL_ERROR'` if omitted. `status` /
`statusCode` mirror `httpStatus` so Express's default error handler (and other frameworks'
conventions) answer with the right status instead of turning every 401/429 into a 500. `cause` is
set only when provided (e.g. wrapping a Mongo or `jsonwebtoken` error) — useful for logging, never
meant to be exposed to API clients.

## `isIdpError(err)`

```ts
function isIdpError(err: unknown): err is IdpError
```

Type guard — `err instanceof IdpError`. Use it to distinguish package errors from bugs in your
own error-handling middleware (e.g. to decide whether to log at `warn` vs `error` level).

## `ERROR_CODES`

`ERROR_CODES` is a stable, non-exhaustive-enforced catalogue of every `code` value the package's
handlers may throw — useful as a reference when writing client-side error mapping, not a runtime
validation list.

| Code | Typical `httpStatus` | Category |
|---|---|---|
| `INTERNAL_ERROR` | 500 | Generic — also what `idpErrorHandler()` answers for any non-`IdpError` |
| `INVALID_REQUEST` | 400 | Generic — also a malformed body under `idpErrorHandler()` |
| `MISSING_REQUIRED_FIELDS` | 400 | Generic |
| `VALIDATION_ERROR` | 400 | Generic — thrown by `validateBody`/`validateQuery` on zod parse failure |
| `SERVICE_UNAVAILABLE` | 503 | Generic — the remote services-JWKS lookup behind `verifyServiceTokenRemote` can't reach the IdP and has no keys from an earlier fetch |
| `NOT_FOUND` | 404 | Generic |
| `RATE_LIMIT_EXCEEDED` | 429 | Generic — thrown by `enforceRateLimit` |
| `RATE_LIMITER_UNAVAILABLE` | 503 | Generic — rate-limiter backend errored (or `MemoryRateLimiter` is full) on a fail-closed key — every limit except token refresh; see [Rate Limiter Interface](rate-limiter-interface.md) |
| `FEATURE_DISABLED` | 404 | Generic — `setupMfaHandler`/`confirmMfaHandler` with `config.mfa.enabled: false` |
| `CSRF_ORIGIN_REJECTED` | 403 | Generic — a state-changing request authenticated by the session **cookie**, or any browser request to an endpoint that sets or clears session cookies (`/login`, `/refresh`, `/logout`, `/mfa/verify`, `/magic-link/verify`, `/webauthn/authentication/verify`, `/webauthn/mfa/verify`), came from an `Origin` that is neither the issuer's nor in `cookies.trustedOrigins`; see [Middleware](middleware.md) |
| `PAYLOAD_TOO_LARGE` | 413 | Generic — only produced by `idpErrorHandler()`, for an oversized body |
| `COOKIE_CONFLICT` | 400 | Generic — a request carried a session cookie (or an SSO binding cookie) twice, as a cookie planted by a sibling subdomain would make it (possible in practice only with `cookies.domain`, where the names are `__Secure-` rather than `__Host-`). Sign in again; find and remove the planted cookie |
| `AUTH_REQUIRED` | 401 | AuthN — `authContextMiddleware`, no token presented and not `optional` |
| `UNAUTHENTICATED` | 401 | AuthN — handler-level check when `req.auth` is missing; also a wrong or non-covering bootstrap secret at `POST /internal/service-keys` |
| `FORBIDDEN` | 403 | AuthN — `requireServiceCallerMiddleware` (caller not allowed, or a shared-secret caller without `serviceMesh.allowLegacySecretCallers`), a service name outside `serviceMesh.allowedServiceNames`, or the shared `bootstrapSecret` registering a name that has its own `bootstrapSecrets` entry |
| `INVALID_TOKEN` | 401 | AuthN — malformed/unverifiable token, not an access token, or the wrong token kind/audience for the route (e.g. a token issued to a third-party OAuth2 client, presented at a first-party route) |
| `TOKEN_EXPIRED` | 401 | AuthN |
| `TOKEN_REVOKED` | 401 | AuthN — presented token's `jti` found in the revocation cache, or (with `session.verifyOnEachRequest`) its session row is missing, revoked, expired, or another user's; also a refresh or a login that raced "log out everywhere" / a password reset, a refresh racing reuse detection of its family, and a `client_credentials` token whose client is gone or no longer `ACTIVE` |
| `REAUTHENTICATION_REQUIRED` | 401 | AuthN — `requireRecentAuth()`: the user's last real login is older than `session.recentAuthMaxAgeSeconds` (default 15 min), or unknown. Send the user through a login and retry |
| `CACHE_UNAVAILABLE` | 503 | AuthN — cache adapter errored during a revocation check with `session.verifyOnEachRequest: false` (fail-closed). With it on, a cache error is logged and the session store decides |
| `SESSION_STORE_UNAVAILABLE` | 503 | AuthN — `sessionRepository.findByJti` errored during the per-request session check (fail-closed); see [Middleware](middleware.md) |
| `INVALID_CREDENTIALS` | 401 | Credentials — also every password, right or wrong, while password login is locked (failed-password lockout: `security.maxFailedLoginAttempts` per `security.accountLockDurationMs`, counted in the attempt counter as `password-login:<userId>`), on a `PENDING_VERIFICATION` account, or on a deleted account |
| `EMAIL_AND_PASSWORD_REQUIRED` | 400 | Credentials |
| `EMAIL_REQUIRED` | 400 | Credentials |
| `USER_NOT_FOUND` | 404 | Credentials — authenticated routes whose user row has gone; never on the unauthenticated email endpoints |
| `USER_ALREADY_EXISTS` | 409 | Credentials — **defined but never thrown**; `registerHandler` is enumeration-safe (see below) |
| `USER_NOT_ACTIVE` | 403 | Credentials |
| `ACCOUNT_LOCKED` | 423 | Credentials — an **administrative** lock only: status `LOCKED` without a `lockUntil`, set by your app (magic-link, passkey, or password login with the right password). The failed-password lockout no longer changes the status — it locks password login only (`INVALID_CREDENTIALS`), and every other method keeps working |
| `ACCOUNT_SUSPENDED` | 403 | Credentials — status `SUSPENDED`/`DISABLED` |
| `PENDING_VERIFICATION` | 403 | Credentials — status `INVITED` (and `PENDING_VERIFICATION` where a flow reaches `assertUsableStatus`). Password login on a `PENDING_VERIFICATION` account answers `INVALID_CREDENTIALS` instead (0.4.0) |
| `CANNOT_DELETE_USER` | 400 | Credentials |
| `EMAIL_ALREADY_VERIFIED` | 400 | Credentials — **no longer thrown** (0.4.0): resend-verification answers `{ status: 'ok' }` for every address |
| `INVALID_OR_EXPIRED_TOKEN` | 400 | Credentials — opaque token/code (reset/verify/magic-link) not found or expired; also verify-email for an unknown or already-verified address |
| `REGISTRATION_PASSWORD_REQUIRED` | 400 | Credentials — verify-email on an address registered more than once before verification, without the `password` of the code's registration (or with a wrong one); the code stays usable (for a code, the attempt counts toward `security.verificationCodeLockout`) |
| `VERIFICATION_LOCKED` | 429 | Credentials — per-address lockout on the 6-digit verification **code** (`security.verificationCodeLockout`, default 5 wrong codes per hour, locked 15 min); answered the same for unknown, verified and pending addresses. The outstanding codes are cleared, but the emailed **link** (`token`) still works — it has no attempt budget |
| `CURRENT_PASSWORD_INCORRECT` | 400 | Credentials |
| `PASSWORD_CHANGE_LOCKED` | 429 | Credentials — `/password/change`: per-account limit on wrong current passwords (`security.passwordChangeLockout`, default 5 per hour, locked an hour); returned for the attempt that exhausts it and every attempt while locked |
| `REFRESH_TOKEN_REQUIRED` | 400 | Session |
| `INVALID_REFRESH_TOKEN` | 401 | Session — unknown, revoked or rotated token, an OAuth2 refresh token presented at `/refresh`, or a session family past `session.absoluteLifetimeSeconds` |
| `REFRESH_TOKEN_NOT_FOUND` | 404 | Session |
| `MFA_ALREADY_ENABLED` | 400 | MFA |
| `MFA_NOT_ENABLED` | 400 | MFA |
| `MFA_SETUP_REQUIRED` | 400 | MFA |
| `INVALID_MFA_CODE` | 400 | MFA — wrong or already-used TOTP code or recovery code |
| `INVALID_MFA_CHALLENGE_TOKEN` | 401 | MFA — invalid, expired or already-used challenge token, one issued before the account's last password change, or one without this issuer's `iss` and `aud` `<issuer>#mfa-challenge` (e.g. from another environment sharing a signing key, or a 0.3.x token) |
| `MFA_LOCKED` | 429 | MFA — per-account second-factor lockout; returned for the attempt that exhausts the budget and every attempt while locked, right code or not (see [MFA](mfa.md#per-account-lockout)) |
| `MFA_ENCRYPTION_NOT_CONFIGURED` | 500 | MFA — an encrypted secret was found, or one must be written, with no `mfa.encryptionKey`/`secretCipher` |
| `MFA_SECRET_NOT_ENCRYPTED` | 500 | MFA — a plain-text secret was found with `mfa.requireEncrypted: true`; run `migrateMfaSecrets()` |
| `MFA_SECRET_UNREADABLE` | 500 | MFA — stored secret failed to decrypt (tampered, wrong key, unknown key id); fails closed, no tokens issued |
| `UNKNOWN_KID` | 404 | OAuth2/OIDC/JWKS |
| `KEY_NOT_ALLOWED` | 403 | OAuth2/OIDC/JWKS |
| `INVALID_REDIRECT_URI` | 400 | OAuth2/OIDC/JWKS |
| `INVALID_CLIENT` | 401 | OAuth2 — client authentication failed at `/oauth2/token`, `/token/revoke` or `/token/introspect`. Unknown, inactive and wrong-secret clients all get the same answer |
| `INVALID_GRANT` | 400 | OAuth2 — bad, expired or reused authorization code or refresh token, `redirect_uri` mismatch, PKCE failure, inactive user, a family past its lifetime, or an authorization code issued before the user's sessions were revoked, whose authorizing session has since been revoked (or is gone), or whose consent was withdrawn/re-granted since |
| `INVALID_SCOPE` | 400 | OAuth2 — requested scope outside the client's `allowedScopes` |
| `UNAUTHORIZED_CLIENT` | 400 | OAuth2 — grant type not allowed for the client |
| `UNSUPPORTED_GRANT_TYPE` | 400 | OAuth2 |
| `INVALID_CONSENT_CHALLENGE` | 400 | OAuth2 — `/oauth2/authorize/confirm` or `/deny` with an unknown, expired, already-used or another user's `consent_challenge` |
| `SSO_PROVIDER_ERROR` | 400 | SSO — currently only an Apple `id_token` that wasn't issued for this login (nonce, `iss`, `aud`, `exp`). Other provider-communication failures (code exchange, profile fetch, timeouts) throw a plain `Error`, which `idpErrorHandler()` answers 500 `INTERNAL_ERROR` — see [SSO / Social Login](sso-social-login.md). An `error` returned by the provider itself isn't an exception: the browser is redirected back with `error=provider_error` |
| `INVALID_SSO_PROVIDER` | 400 | SSO — unknown or unconfigured provider |
| `SSO_PROVIDER_NOT_CONFIGURED` | 400/500 | SSO — **defined but never thrown** (the unconfigured case throws `INVALID_SSO_PROVIDER`) |
| `INVALID_SSO_STATE` | 400 | SSO — state missing, expired or already used, or the per-attempt binding cookie is missing or doesn't match |
| `OAUTH_CLIENT_EXISTS` | 409 | OAuth clients |
| `OAUTH_CLIENT_NOT_FOUND` | 404 / 400 | OAuth clients — 404 on the client-administration routes; 400 at `/oauth2/authorize`, `/oauth2/consent` and end-session for an unknown or inactive client |
| `SERVICE_TOKEN_INVALID` | 401 | Service mesh — includes tokens without `exp`, living over 5 minutes, or with `iat` in the future |
| `SERVICE_AUTH_FAILED` | 401 | Service mesh — `serviceContextMiddleware` found no valid token or shared secret |
| `SERVICE_NOT_CONFIGURED` | 500 | Service mesh — `ownServiceName` / `expectedAud` missing, or no `sharedSecret` while a secret-accepting `tokenMode` needs one |
| `SERVICE_NAME_TAKEN` | 409 | Service mesh — the shared `bootstrapSecret` tried to register a name that already has a key; rotating a key needs that service's own `bootstrapSecrets` entry. Also the losers of concurrent first registrations of one new name with the shared secret (the earliest-registered key keeps the name; the others' keys are revoked) |
| `SERVICE_KEY_REVOKED` | 409 | Service mesh — `POST /internal/service-keys` with a key that was revoked; a revoked key is never re-activated, so the service must generate a new key pair |
| `WEBAUTHN_NOT_CONFIGURED` | 500 | WebAuthn — `config.webauthn` incomplete at first use |
| `WEBAUTHN_CHALLENGE_EXPIRED` | 400 | WebAuthn |
| `WEBAUTHN_VERIFICATION_FAILED` | 400/401 | WebAuthn |
| `CREDENTIAL_NOT_FOUND` | 400 / 404 | WebAuthn — 400 during a ceremony; 404 from `DELETE /me/passkeys/:credentialId` for a passkey the caller doesn't own |
| `MONGO_TRANSACTIONS_UNSUPPORTED` | 500 | Startup only — thrown by `initIdentityProvider()`, not a request-time error, and not in `ERROR_CODES` (see [Bootstrap & Config](bootstrap-config.md)) |

`EMAIL_AND_PASSWORD_REQUIRED`, `EMAIL_REQUIRED`, `CANNOT_DELETE_USER`, `USER_ALREADY_EXISTS`,
`EMAIL_ALREADY_VERIFIED`, `SSO_PROVIDER_NOT_CONFIGURED` and the generic `NOT_FOUND` are defined in
the catalogue but not currently constructed anywhere in the codebase. If you're building an
exhaustive client-side switch over every code in this table, these branches are currently dead —
this is what "non-exhaustive-enforced" above means in practice: the catalogue is a superset of
what's actually thrown today.

The OAuth2 token endpoint uses the RFC 6749 codes (`INVALID_CLIENT`, `INVALID_GRANT`,
`INVALID_SCOPE`, `UNAUTHORIZED_CLIENT`, `UNSUPPORTED_GRANT_TYPE`): a user who is no longer active is
`INVALID_GRANT` (400) there, not `USER_NOT_ACTIVE`. See
[OAuth2 Authorization Server](oauth2-authorization-server.md).

Startup and configuration failures (missing or short secrets, bad signing keys, bad rate-limit
rules, a missing SSO allowlist, ...) are plain `Error`s thrown from `initIdentityProvider()`, not
`IdpError`s — see [Bootstrap & Config](bootstrap-config.md#initidentityproviderconfig).

## Enumeration-safety pattern

Several handlers deliberately answer the same way for real and non-existent accounts to avoid
leaking which emails are registered — this is normal, not a bug, if you see a 200/201 (or a
generic 400) where you expected a 404/409:

- `registerHandler` — an already-registered email still gets `201 { status: 'ok' }` (this is also
  why `USER_ALREADY_EXISTS` is never thrown).
- `verifyEmailHandler` — an unknown or already-verified address gets the same 400
  `INVALID_OR_EXPIRED_TOKEN` as a wrong code (so a second click on a used link is now a 400, not
  `ok`).
- `resendVerificationEmailHandler` — always `{ status: 'ok' }`, sent before the address is looked up.
- `forgotPasswordHandler` — always `{ status: 'ok' }`, sent before the address is looked up.
- `requestMagicLinkHandler` — `{ status: 'ok' }` for an unknown email when
  `allowSignupViaMagicLink: false`, and for a deleted account.
- `generateAuthenticationOptionsHandler` (WebAuthn) — ignores `email` unless
  `webauthn.allowCredentialsByEmail: true`, and then answers an unknown address with a stable decoy
  credential id rather than a distinguishable error.
- `loginHandler` — while password login is locked, and on a pending account, every password
  answers `INVALID_CREDENTIALS`; an unknown or passwordless account compares a dummy hash of the
  configured `bcryptRounds` cost.

On register and magic-link request, the email hooks (and their audit events) are started but not
awaited (resend-verification and forgot-password do all their work after responding), so
response time doesn't reveal whether an email was sent either.

## Related

- [Bootstrap & Config](bootstrap-config.md)
- [Middleware](middleware.md) — `requireRecentAuth()`, the CSRF origin check.
- [Rate Limiter Interface](rate-limiter-interface.md) — a backend error fails closed (`RATE_LIMITER_UNAVAILABLE`) on every limit except token refresh.
- [Cache Interface](cache-interface.md) — `CACHE_UNAVAILABLE` fails closed for revocation checks.
- [MFA](mfa.md) — `MFA_LOCKED` and the `MFA_SECRET_*` codes.
