---
title: "Router & Validation Schemas"
package: "@okeav/idp-core"
category: "api-reference"
tags: ["express", "router", "zod", "validation"]
description: "buildRouter() and the full mounted route table, plus the exported zod schemas object."
---

# Router & Validation Schemas

## `buildRouter(opts?)`

```ts
function buildRouter(opts?: {
  clientManagement?: { middleware: RequestHandler | RequestHandler[] };
  features?: Partial<Record<'magicLink' | 'webauthn' | 'sso' | 'oauth2' | 'oidc' | 'serviceMesh', boolean>>;
  ownServiceName?: string; // deprecated — never had any effect; accepted and ignored
}): express.Router
```

Assembles a fully-wired `express.Router()` covering the routes this package implements, using
sensible default paths. Entirely optional — if your app wants different paths or custom rate
limiting, mount the individual handler exports on your own router instead.

**`opts.clientManagement`** — OAuth2 client administration (the seven `/oauth2/clients*` routes
below) is **not mounted unless this is given** (since 0.3.0; without it every client path is a
plain 404). This package has no admin-role concept, so you supply the admin
authentication/authorization as `middleware` — one function or an array. The routes are mounted on
a sub-router whose first handlers are that middleware, so it runs before every client route and
can refuse. `buildRouter` throws at startup if `clientManagement` is given without at least one
middleware function (missing `middleware`, empty array, or a non-function entry). Independent of
`features.oauth2`.

```js
app.use('/auth', buildRouter({ clientManagement: { middleware: [requireAdmin] } })); // requireAdmin: your own middleware
```

**`opts.features`** — each of `magicLink`, `webauthn`, `sso`, `oauth2`, `oidc`, `serviceMesh`
defaults to `true`; set one to `false` to leave that surface's routes (marked in the tables below)
unmounted. An unknown key throws. Password/email auth, `/me*`, MFA, and JWKS routes are always
mounted.

`serviceContextMiddleware` is also re-exported alongside `buildRouter` for building your own
protected internal routes alongside it.

### What the router does for every route

- **`Cache-Control: no-store`** on every response (they may carry tokens, codes or account data).
  The JWKS handlers (`/.well-known/jwks.json`, `/keys/:kid`) override it with
  `public, max-age=300`, and the discovery document with `public, max-age=<ttls.discoveryCache>`
  (default 3600). The OAuth2 token, revoke and introspect responses also send `Pragma: no-cache`.
- **No error responses of its own.** Handlers call `next(err)` with an `IdpError`; mount
  [`idpErrorHandler()`](middleware.md#idperrorhandleropts) (or your own handler that shows a
  message only when `err.expose`) after the router:

  ```js
  import express from 'express';
  import { buildRouter, cookieParser, idpErrorHandler } from '@okeav/idp-core';

  app.use(cookieParser());   // session cookies, and the SSO binding cookie
  app.use(express.json());
  app.use('/auth', buildRouter());
  app.use(idpErrorHandler({ logger }));
  ```

- **`authContextMiddleware()` accepts first-party tokens only** on every IdP route below, except
  `/userinfo`, which accepts only OAuth2 user tokens (`accept: ['oauth2-user']`). Cookie-authenticated
  state-changing requests pass the [CSRF origin check](middleware.md#csrf-origin-check)
  (`cookies.trustedOrigins`) — and so does every request to the routes that set session cookies
  (`/login`, `/refresh`, `/mfa/verify`, `/magic-link/verify`, `/webauthn/authentication/verify`,
  `/webauthn/mfa/verify`), checked inside the handler.
- **Rate limits** are applied inside the handlers (listed in the *Rate limit* column — the
  `config.rateLimiting` key, then the default). All of them fail **closed** (a limiter backend
  error → 503 `RATE_LIMITER_UNAVAILABLE`) except `refreshToken`. See
  [Rate Limiter Interface](rate-limiter-interface.md).

## Full route table

Mount `buildRouter()` under a prefix, e.g. `app.use('/auth', buildRouter())` — paths below are
relative to that prefix (except the two `/.well-known/*` routes, which are conventionally mounted
at the application root regardless of prefix — see note below).

### Password / email identity
| Method | Path | Middleware | Rate limit |
|---|---|---|---|
| POST | `/register` | `validateBody(registerSchema)` | `register` (10/h per IP), `verificationEmailByEmail` (3/h per address) |
| POST | `/register/verify-email` | `validateBody(verifyEmailSchema)` | `emailVerification` (20/15min per IP); plus `security.verificationCodeLockout` per address (6-digit codes only) |
| POST | `/register/resend-verification` | `validateBody(resendVerificationSchema)` | `register`, `verificationEmailByEmail` |
| POST | `/login` | `validateBody(loginSchema)` | `login` (10/15min per IP), `loginByEmail` (5/15min per address); plus the password-login lockout per account (`security.maxFailedLoginAttempts`) |
| POST | `/mfa/verify` | `validateBody(verifyMfaChallengeSchema)` | `mfaChallenge` (5/15min per IP); plus `mfa.lockout` per account |
| POST | `/refresh` | `validateBody(refreshSchema)` — refresh token from the body or the refresh cookie (body wins) | `refreshToken` (30/min per IP, fail-open) |
| POST | `/logout` | `validateBody(logoutSchema)` — `refreshToken` in the body is optional; the refresh cookie (`__Host-refresh_token`) is read when it's omitted. CSRF origin check on every browser request | — |
| POST | `/logout/all` | `authContextMiddleware()` | — |
| POST | `/password/forgot` | `validateBody(forgotPasswordSchema)` | `passwordReset` (3/h per IP), `passwordResetByEmail` (3/h per address) |
| POST | `/password/reset` | `validateBody(resetPasswordSchema)` | — |
| POST | `/password/change` | `authContextMiddleware()`, `validateBody(changePasswordSchema)` | `security.passwordChangeLockout` per account (wrong current passwords) |

### Magic link — `features.magicLink`
| Method | Path | Middleware | Rate limit |
|---|---|---|---|
| POST | `/magic-link/request` | `validateBody(requestMagicLinkSchema)` | `magicLink` (3/h per IP), `magicLinkByEmail` (3/h per address) |
| POST | `/magic-link/verify` | `validateBody(verifyMagicLinkSchema)` | — |

### Self-service identity ("me")
| Method | Path | Middleware |
|---|---|---|
| GET | `/me` | `authContextMiddleware()` |
| PATCH | `/me` | `authContextMiddleware()`, `validateBody(updateProfileSchema)` |
| DELETE | `/me` | `authContextMiddleware()`, **`requireRecentAuth()`** |
| GET | `/me/sessions` | `authContextMiddleware()` |
| DELETE | `/me/sessions/:id` | `authContextMiddleware()` |
| DELETE | `/me/sessions` | `authContextMiddleware()` |

### MFA
| Method | Path | Middleware |
|---|---|---|
| GET | `/me/mfa` | `authContextMiddleware()` |
| POST | `/me/mfa/setup` | `authContextMiddleware()`, **`requireRecentAuth()`** |
| POST | `/me/mfa/confirm` | `authContextMiddleware()`, **`requireRecentAuth()`**, `validateBody(confirmMfaSchema)` |
| DELETE | `/me/mfa` | `authContextMiddleware()`, `validateBody(disableMfaSchema)` |
| POST | `/me/mfa/recovery-codes` | `authContextMiddleware()`, `validateBody(regenerateRecoveryCodesSchema)` |

### WebAuthn / passkeys — `features.webauthn`
| Method | Path | Middleware | Rate limit |
|---|---|---|---|
| POST | `/webauthn/registration/options` | `authContextMiddleware()`, **`requireRecentAuth()`**, `validateBody(registrationOptionsSchema)` | — |
| POST | `/webauthn/registration/verify` | `authContextMiddleware()`, **`requireRecentAuth()`**, `validateBody(verifyRegistrationSchema)` | — |
| GET | `/me/passkeys` | `authContextMiddleware()` | — |
| DELETE | `/me/passkeys/:credentialId` | `authContextMiddleware()`, **`requireRecentAuth()`** | — |
| POST | `/webauthn/authentication/options` | `validateBody(authenticationOptionsSchema)` | `webauthnAuthentication` (60/5min per IP) |
| POST | `/webauthn/authentication/verify` | `validateBody(verifyAuthenticationSchema)` | `webauthnAuthentication` |
| POST | `/webauthn/mfa/options` | `validateBody(mfaWebauthnOptionsSchema)` | — |
| POST | `/webauthn/mfa/verify` | `validateBody(verifyMfaWebauthnSchema)` | `mfaChallenge`; plus `mfa.lockout` per account |

Routes marked **`requireRecentAuth()`** answer 401 `REAUTHENTICATION_REQUIRED` unless the user
actually logged in within `session.recentAuthMaxAgeSeconds` (default 15 minutes) — a refreshed
token keeps its original login time. See [Middleware](middleware.md#requirerecentauthopts).

### OAuth2 authorization server — `features.oauth2`
| Method | Path | Middleware | Rate limit |
|---|---|---|---|
| GET | `/oauth2/authorize` | `validateQuery(authorizeQuerySchema)`, `authContextMiddleware({ optional: true })` | — |
| POST | `/oauth2/authorize/confirm` | `authContextMiddleware()`, `validateBody(confirmAuthorizeSchema)` — `{ consent_challenge }` | — |
| POST | `/oauth2/authorize/deny` | `authContextMiddleware()`, `validateBody(denyAuthorizeSchema)` — `{ consent_challenge }` | — |
| POST | `/oauth2/token` | `validateBody(tokenSchema)` — client auth by HTTP Basic or body | `oauth2Token` (120/min per IP) |
| POST | `/oauth2/token/revoke` | `validateBody(revokeTokenSchema)` — authenticates the calling **client** | `oauth2Token` |
| POST | `/oauth2/token/introspect` | `validateBody(introspectTokenSchema)` — authenticates the calling **confidential client** (no user token) | `oauth2Token` |
| GET | `/oauth2/consent` | `authContextMiddleware()`, `validateQuery(consentQuerySchema)` | — |
| GET | `/oauth2/consent/sessions` | `authContextMiddleware()` | — |
| DELETE | `/oauth2/consent/sessions/:clientId` | `authContextMiddleware()` | — |

### OAuth2 client management — only with `opts.clientManagement`
Every route runs behind `clientManagement.middleware` first.

| Method | Path | Middleware |
|---|---|---|
| POST | `/oauth2/clients` | `validateBody(registerOAuthClientSchema)` |
| GET | `/oauth2/clients` | — |
| GET | `/oauth2/clients/:clientId` | — |
| PATCH | `/oauth2/clients/:clientId` | `validateBody(updateOAuthClientSchema)` |
| POST | `/oauth2/clients/:clientId/approve` | — |
| POST | `/oauth2/clients/:clientId/rotate-secret` | — |
| DELETE | `/oauth2/clients/:clientId` | — |

> **Upgrading from 0.2.x**: these routes used to be mounted unauthenticated. If you administer
> OAuth clients over HTTP, pass `clientManagement: { middleware: [yourAdminAuth] }`; if you had a
> workaround that 404'd `/oauth2/clients*` in front of `buildRouter()`, remove it. To keep them off
> HTTP entirely, omit the option and call the handlers (or the repository) from your own admin
> tooling.

### OIDC — `features.oidc`
| Method | Path | Middleware |
|---|---|---|
| GET | `/userinfo` | `authContextMiddleware({ accept: ['oauth2-user'] })` — the one route that takes a token issued to an OAuth2 client |
| GET | `/oidc/end-session` | `authContextMiddleware({ optional: true })` — signed in without an `id_token_hint`, answers `{ action: 'logout_confirmation_required' }` |
| POST | `/oidc/end-session` | `express.urlencoded()`, `authContextMiddleware({ optional: true })` — the confirmed request (JSON or form body); trusted origins only |
| GET | `/.well-known/openid-configuration` | — |

### SSO — `features.sso`
| Method | Path | Middleware | Rate limit |
|---|---|---|---|
| GET | `/sso/:provider` | `validateQuery(ssoInitiateQuerySchema)` | `ssoInitiate` (30/5min per IP) |
| GET | `/sso/:provider/callback` | — | — |
| POST | `/sso/:provider/callback` | `express.urlencoded({ extended: false })` (Apple's `form_post` callback) | — |

The SSO routes need `cookie-parser` mounted before the router: `GET /sso/:provider` sets a
per-attempt binding cookie that the callback requires.

### JWKS — always mounted
| Method | Path | Middleware |
|---|---|---|
| GET | `/.well-known/jwks.json` | — |
| GET | `/keys/:kid` | — |

### Service mesh — `features.serviceMesh`
| Method | Path | Middleware | Rate limit |
|---|---|---|---|
| POST | `/internal/service-keys` | `s2sBootstrapMiddleware` | `serviceKeyRegistration` (20/15min per IP) |
| GET | `/.well-known/services-jwks.json` | — | — |

> **Note on `.well-known` paths**: `buildRouter()` mounts `/.well-known/jwks.json`,
> `/.well-known/openid-configuration`, and `/.well-known/services-jwks.json` **relative to
> whatever prefix you mount the router under** (e.g. `/auth/.well-known/jwks.json` if mounted at
> `/auth`). Per RFC 8615, well-known URIs are conventionally expected at the application root
> (`/.well-known/...`) — if OIDC/JWKS discovery clients expect the root path, mount those three
> routes separately at `/` rather than relying on `buildRouter()`'s prefix, or mount the whole
> router at `/`.

## `schemas`

```ts
const schemas: Record<string, { parse: (input: unknown) => unknown }>
```

Every zod schema used internally by `buildRouter()`, merged into one flat object — re-export or
extend in your own routes if you mount handlers individually rather than using `buildRouter()`.
Source modules: `password-auth/schemas.js`, `mfa/schemas.js`, `oauth2/schemas.js`,
`sso/schemas.js`, `magic-link/schemas.js`, `webauthn/schemas.js`. Import as:

```js
import { schemas, validateBody, registerHandler } from '@okeav/idp-core';
app.post('/custom-register-path', validateBody(schemas.registerSchema), registerHandler);
```

Rules worth knowing (most body schemas are `.strict()` — unknown keys are a 400
`VALIDATION_ERROR`):

| Schema | Notes |
|---|---|
| `registerSchema`, `resetPasswordSchema`, `changePasswordSchema` | New passwords: 8–128 characters **and at most 72 bytes of UTF-8** (bcrypt's limit — longer is refused, not truncated), with upper- and lowercase, a number and a special character. `registerSchema.metadata` is accepted but persisted only with `registration.acceptMetadata: true`. |
| `loginSchema` | `password` is 1–1024 characters, no policy (legacy passwords must still log in). |
| `verifyEmailSchema` | `{ email, token?, code?, password? }` — `token` or `code` required; `code` at most 128 characters; `password` 1–1024 characters, no policy — needed only for an address registered more than once before verification (else 400 `REGISTRATION_PASSWORD_REQUIRED`). |
| `refreshSchema`, `logoutSchema` | `{ refreshToken? }` — a string of at most 512 characters; the body may be omitted. |
| `updateProfileSchema` | `avatarUrl` must be `https`; `locale` a BCP 47 tag; `zoneinfo` an IANA zone name. |
| `disableMfaSchema`, `regenerateRecoveryCodesSchema` | `{ password?, code }` — `password` is required by the handler only when the account has one; `code` is a current TOTP code. |
| `verifyMfaChallengeSchema` | `code` 6–32 characters, so a recovery code (`XXXXX-XXXXX-XXXXX-XXXXX`, 23 characters) fits. |
| `authorizeQuerySchema` | `nonce` (≤ 512 chars), `prompt` (≤ 100 chars; its values are checked by the handler), `max_age` (a non-negative integer of seconds, ≤ 10 digits), and PKCE: `code_challenge` must be a 43-character base64url S256 value and requires `code_challenge_method=S256` (`plain` is refused). Not `.strict()`. |
| `confirmAuthorizeSchema`, `denyAuthorizeSchema` | Only `{ consent_challenge }` — the value `/oauth2/authorize` returned. Client, scopes, redirect URI, state, nonce and PKCE come from the stored request, never this body. |
| `tokenSchema` | `client_id`/`client_secret` optional (they may come as HTTP Basic instead); `code_verifier` 43–128 unreserved characters; `.passthrough()`. |
| `revokeTokenSchema`, `introspectTokenSchema` | `{ token, token_type_hint?, client_id?, client_secret? }`. |
| `consentQuerySchema` | `{ client_id }` — a string (`?client_id[$ne]=` is refused). |
| `registerOAuthClientSchema`, `updateOAuthClientSchema` | `redirectUris`/`postLogoutRedirectUris` must be `https`, `http` to a loopback host, or a reverse-DNS private-use scheme, with no fragment or credentials. `updateOAuthClientSchema` also caps `accessTokenTTL` and `idTokenTTL` at 86400 s (24 h) and `refreshTokenTTL` at 31536000 s (1 year), and requires `logoUrl`, `websiteUrl`, `privacyPolicyUrl` and `termsOfServiceUrl` to be `https` URLs (≤ 2048 characters) — they're shown as links on the consent screen. |
| `authenticationOptionsSchema` | `{ email? }` — ignored unless `webauthn.allowCredentialsByEmail: true`. |
| `ssoInitiateQuerySchema` | `redirect_uri` (must also be on `sso.allowedRedirectOrigins`, checked by the handler); `.passthrough()` — extra params reach `resolveAuthContext` as `extra`, limited to 10 short strings, and are attacker-controllable. |

## Related

- [Middleware](middleware.md) — `validateBody`/`validateQuery`/`authContextMiddleware`/`requireRecentAuth`/`idpErrorHandler` semantics.
- Every other API reference file documents the handler behavior behind these routes.
