---
title: "Error Handling"
package: "@okeav/idp-core"
category: "api-reference"
tags: ["errors", "error-handling"]
description: "The IdpError type, isIdpError(), and the full ERROR_CODES catalogue with HTTP statuses."
---

# Error Handling

Every error this package throws is an `IdpError`. The package never shapes an HTTP response body
itself — write one Express error-handling middleware that maps `err.httpStatus`/`err.code` to your
API's response envelope.

```js
app.use((err, req, res, next) => {
  res.status(err.httpStatus || 500).json({ error: err.code || 'INTERNAL_ERROR', message: err.message });
});
```

## `IdpError`

```ts
class IdpError extends Error {
  code: string;
  httpStatus: number; // default 500
  cause?: unknown;
  constructor(opts: { code: string; httpStatus?: number; message?: string; cause?: unknown });
}
```

`name` is always `'IdpError'`. `code` defaults to `'INTERNAL_ERROR'` if omitted. `cause` is set
only when provided (e.g. wrapping a Mongo or `jsonwebtoken` error) — useful for logging, not
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
| `INTERNAL_ERROR` | 500 | Generic |
| `INVALID_REQUEST` | 400 | Generic |
| `MISSING_REQUIRED_FIELDS` | 400 | Generic |
| `VALIDATION_ERROR` | 400 | Generic — thrown by `validateBody`/`validateQuery` on zod parse failure |
| `SERVICE_UNAVAILABLE` | 503 | Generic |
| `NOT_FOUND` | 404 | Generic |
| `RATE_LIMIT_EXCEEDED` | 429 | Generic — thrown by `enforceRateLimit` |
| `AUTH_REQUIRED` | 401 | AuthN — `authContextMiddleware`, no token presented and not `optional` |
| `UNAUTHENTICATED` | 401 | AuthN — handler-level check when `req.auth` is missing |
| `FORBIDDEN` | 403 | AuthN |
| `INVALID_TOKEN` | 401 | AuthN — malformed/unverifiable token |
| `TOKEN_EXPIRED` | 401 | AuthN |
| `TOKEN_REVOKED` | 401 | AuthN — presented token's `jti` found in the revocation cache |
| `CACHE_UNAVAILABLE` | 503 | AuthN — cache adapter errored during a revocation check (fail-closed) |
| `INVALID_CREDENTIALS` | 401 | Credentials |
| `EMAIL_AND_PASSWORD_REQUIRED` | 400 | Credentials |
| `EMAIL_REQUIRED` | 400 | Credentials |
| `USER_NOT_FOUND` | 404 | Credentials |
| `USER_ALREADY_EXISTS` | 409 | Credentials — **defined but never actually thrown**; `registerHandler` is enumeration-safe (see below) and returns `201 { status: 'ok' }` for an already-registered email instead of a distinguishable error |
| `USER_NOT_ACTIVE` | 403 | Credentials |
| `ACCOUNT_LOCKED` | 423 | Credentials — too many failed logins |
| `ACCOUNT_SUSPENDED` | 403 | Credentials — status `SUSPENDED`/`DISABLED` |
| `PENDING_VERIFICATION` | 403 | Credentials — status `PENDING_VERIFICATION`/`INVITED` |
| `CANNOT_DELETE_USER` | 400 | Credentials |
| `EMAIL_ALREADY_VERIFIED` | 400 | Credentials |
| `INVALID_OR_EXPIRED_TOKEN` | 400 | Credentials — opaque token (reset/verify/magic-link) not found/expired |
| `CURRENT_PASSWORD_INCORRECT` | 400 | Credentials |
| `REFRESH_TOKEN_REQUIRED` | 400 | Session |
| `INVALID_REFRESH_TOKEN` | 401 | Session |
| `REFRESH_TOKEN_NOT_FOUND` | 404 | Session |
| `MFA_ALREADY_ENABLED` | 400 | MFA |
| `MFA_NOT_ENABLED` | 400 | MFA |
| `MFA_SETUP_REQUIRED` | 400 | MFA |
| `INVALID_MFA_CODE` | 400 | MFA |
| `INVALID_MFA_CHALLENGE_TOKEN` | 401 | MFA |
| `UNKNOWN_KID` | 404 | OAuth2/OIDC/JWKS |
| `KEY_NOT_ALLOWED` | 403 | OAuth2/OIDC/JWKS |
| `INVALID_REDIRECT_URI` | 400 | OAuth2/OIDC/JWKS |
| `SSO_PROVIDER_ERROR` | varies | SSO — **listed here but never actually constructed.** Real provider-communication failures (code exchange, profile fetch) throw a plain `Error`, not an `IdpError` with this code — see the provider-communication-failures callout in [SSO / Social Login](sso-social-login.md). `isIdpError(err)` is `false` for these, so a default error-handling middleware collapses them to a generic `INTERNAL_ERROR`/500, not `SSO_PROVIDER_ERROR`. Don't branch on this code. |
| `INVALID_SSO_PROVIDER` | 400 | SSO |
| `SSO_PROVIDER_NOT_CONFIGURED` | 400/500 | SSO |
| `INVALID_SSO_STATE` | 400 | SSO — CSRF-state mismatch or replay |
| `OAUTH_CLIENT_EXISTS` | 409 | OAuth clients |
| `OAUTH_CLIENT_NOT_FOUND` | 404 | OAuth clients |
| `SERVICE_TOKEN_INVALID` | 401 | Service mesh |
| `SERVICE_AUTH_FAILED` | 401 | Service mesh |
| `SERVICE_NOT_CONFIGURED` | 500 | Service mesh |
| `WEBAUTHN_NOT_CONFIGURED` | 500 | WebAuthn — `config.webauthn` incomplete at first use |
| `WEBAUTHN_CHALLENGE_EXPIRED` | 400 | WebAuthn |
| `WEBAUTHN_VERIFICATION_FAILED` | 400/401 | WebAuthn |
| `CREDENTIAL_NOT_FOUND` | 400 | WebAuthn |
| `MONGO_TRANSACTIONS_UNSUPPORTED` | 500 | Startup only — thrown by `initIdentityProvider()`, not a request-time error (see [Bootstrap & Config](bootstrap-config.md)) |

`EMAIL_AND_PASSWORD_REQUIRED`, `EMAIL_REQUIRED`, `CANNOT_DELETE_USER`, and
`SSO_PROVIDER_NOT_CONFIGURED` (the unconfigured-provider case in practice throws
`INVALID_SSO_PROVIDER` — see [SSO / Social Login](sso-social-login.md)) are likewise defined in the
catalogue but not currently constructed anywhere in the codebase, along with the generic
`SERVICE_UNAVAILABLE`/`NOT_FOUND`. If you're building an exhaustive client-side switch over every
code in this table, these branches are currently dead — this is what "non-exhaustive-enforced"
above means in practice: the catalogue is a superset of what's actually thrown today.

`USER_NOT_ACTIVE` is `403` everywhere except the OAuth2 token endpoint's `authorization_code` and
`refresh_token` grants ([OAuth2 Authorization Server](oauth2-authorization-server.md)), where it's
`400` — consistent with that endpoint's convention of `400` for all `invalid_grant`-style
failures, not an inconsistency to work around.

## Enumeration-safety pattern

Several handlers deliberately return `{ status: 'ok' }`/`201` for both real and non-existent
accounts to avoid leaking which emails are registered — this is normal, not a bug, if you see a
200/201 response where you expected a 404/409. Affected endpoints: `registerHandler` (an
already-registered email still gets `201 { status: 'ok' }`, burning the same wall-clock time as a
real registration — this is also why `USER_ALREADY_EXISTS` above is never actually thrown),
`resendVerificationEmailHandler`, `forgotPasswordHandler`, `requestMagicLinkHandler` (when
`allowSignupViaMagicLink: false` and the email is unknown), and
`generateAuthenticationOptionsHandler` (WebAuthn — issues a real, if uncompletable, challenge for
an unknown email rather than a distinguishable error).

## Related

- [Bootstrap & Config](bootstrap-config.md)
- [Rate Limiter Interface](rate-limiter-interface.md) — `RATE_LIMIT_EXCEEDED` fails closed to the client but the *backend* fails open.
- [Cache Interface](cache-interface.md) — `CACHE_UNAVAILABLE` fails closed for revocation checks.
