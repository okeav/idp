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

## Full route table

Mount `buildRouter()` under a prefix, e.g. `app.use('/auth', buildRouter())` — paths below are
relative to that prefix (except the two `/.well-known/*` routes, which are conventionally mounted
at the application root regardless of prefix — see note below).

### Password / email identity
| Method | Path | Middleware |
|---|---|---|
| POST | `/register` | `validateBody(registerSchema)` |
| POST | `/register/verify-email` | `validateBody(verifyEmailSchema)` |
| POST | `/register/resend-verification` | `validateBody(resendVerificationSchema)` |
| POST | `/login` | `validateBody(loginSchema)` |
| POST | `/mfa/verify` | `validateBody(verifyMfaChallengeSchema)` |
| POST | `/refresh` | — |
| POST | `/logout` | `validateBody(logoutSchema)` — `refreshToken` in the body is optional; the `refresh_token` cookie is read when it's omitted |
| POST | `/logout/all` | `authContextMiddleware()` |
| POST | `/password/forgot` | `validateBody(forgotPasswordSchema)` |
| POST | `/password/reset` | `validateBody(resetPasswordSchema)` |
| POST | `/password/change` | `authContextMiddleware()`, `validateBody(changePasswordSchema)` |

### Magic link — `features.magicLink`
| Method | Path | Middleware |
|---|---|---|
| POST | `/magic-link/request` | `validateBody(requestMagicLinkSchema)` |
| POST | `/magic-link/verify` | `validateBody(verifyMagicLinkSchema)` |

### Self-service identity ("me")
| Method | Path | Middleware |
|---|---|---|
| GET | `/me` | `authContextMiddleware()` |
| PATCH | `/me` | `authContextMiddleware()`, `validateBody(updateProfileSchema)` |
| DELETE | `/me` | `authContextMiddleware()` |
| GET | `/me/sessions` | `authContextMiddleware()` |
| DELETE | `/me/sessions/:id` | `authContextMiddleware()` |
| DELETE | `/me/sessions` | `authContextMiddleware()` |

### MFA
| Method | Path | Middleware |
|---|---|---|
| GET | `/me/mfa` | `authContextMiddleware()` |
| POST | `/me/mfa/setup` | `authContextMiddleware()` |
| POST | `/me/mfa/confirm` | `authContextMiddleware()`, `validateBody(confirmMfaSchema)` |
| DELETE | `/me/mfa` | `authContextMiddleware()`, `validateBody(disableMfaSchema)` |
| POST | `/me/mfa/recovery-codes` | `authContextMiddleware()`, `validateBody(regenerateRecoveryCodesSchema)` |

### WebAuthn / passkeys — `features.webauthn`
| Method | Path | Middleware |
|---|---|---|
| POST | `/webauthn/registration/options` | `authContextMiddleware()`, `validateBody(registrationOptionsSchema)` |
| POST | `/webauthn/registration/verify` | `authContextMiddleware()`, `validateBody(verifyRegistrationSchema)` |
| POST | `/webauthn/authentication/options` | `validateBody(authenticationOptionsSchema)` |
| POST | `/webauthn/authentication/verify` | `validateBody(verifyAuthenticationSchema)` |
| POST | `/webauthn/mfa/options` | `validateBody(mfaWebauthnOptionsSchema)` |
| POST | `/webauthn/mfa/verify` | `validateBody(verifyMfaWebauthnSchema)` |

### OAuth2 authorization server — `features.oauth2`
| Method | Path | Middleware |
|---|---|---|
| GET | `/oauth2/authorize` | `validateQuery(authorizeQuerySchema)`, `authContextMiddleware({ optional: true })` |
| POST | `/oauth2/authorize/confirm` | `authContextMiddleware()`, `validateBody(confirmAuthorizeSchema)` |
| POST | `/oauth2/authorize/deny` | `authContextMiddleware()`, `validateBody(denyAuthorizeSchema)` |
| POST | `/oauth2/token` | `validateBody(tokenSchema)` |
| POST | `/oauth2/token/revoke` | `validateBody(revokeTokenSchema)` |
| POST | `/oauth2/token/introspect` | `authContextMiddleware()`, `validateBody(introspectTokenSchema)` |
| GET | `/oauth2/consent` | `authContextMiddleware()` |
| GET | `/oauth2/consent/sessions` | `authContextMiddleware()` |
| DELETE | `/oauth2/consent/sessions/:clientId` | `authContextMiddleware()` |

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
| GET | `/userinfo` | `authContextMiddleware()` |
| GET | `/oidc/end-session` | `authContextMiddleware({ optional: true })` |
| GET | `/.well-known/openid-configuration` | — |

### SSO — `features.sso`
| Method | Path | Middleware |
|---|---|---|
| GET | `/sso/:provider` | `validateQuery(ssoInitiateQuerySchema)` |
| GET | `/sso/:provider/callback` | — |
| POST | `/sso/:provider/callback` | `express.urlencoded({ extended: false })` (Apple's `form_post` callback) |

### JWKS — always mounted
| Method | Path | Middleware |
|---|---|---|
| GET | `/.well-known/jwks.json` | — |
| GET | `/keys/:kid` | — |

### Service mesh — `features.serviceMesh`
| Method | Path | Middleware |
|---|---|---|
| POST | `/internal/service-keys` | `s2sBootstrapMiddleware` |
| GET | `/.well-known/services-jwks.json` | — |

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
import { schemas } from '@okeav/idp-core';
app.post('/custom-register-path', validateBody(schemas.registerSchema), registerHandler);
```

## Related

- [Middleware](middleware.md) — `validateBody`/`validateQuery`/`authContextMiddleware` semantics.
- Every other API reference file documents the handler behavior behind these routes.
