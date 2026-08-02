# @okeav/idp-core Documentation

Reference documentation and runnable examples for
[`@okeav/idp-core`](https://github.com/okeav/idp) — a standalone, pluggable identity provider for
Node.js/TypeScript backends (OAuth2/OIDC authorization server, password + MFA + WebAuthn/passkeys
+ magic-link + social login, session management, rate limiting, outbound webhooks, and
service-to-service JWKS trust).

This tree is content-only — no build step, no MCP/search server yet (see "Structure" below for why
it's laid out this way).

## Layout

```
docs/
  api/         one file per concept area — purpose, full signatures, config, errors, return shapes
  examples/    one working, runnable scenario per file
```

This tree lives in the `@okeav/idp-core` package repo itself (the source it documents), not on the
okeav platform — the platform pulls a copy of it via a manual sync, not an automatic trigger.

Every file carries the same YAML frontmatter (`title`, `package`, `category`, `tags`,
`description`) so the set can later be indexed/filtered programmatically without a rewrite —
`category` is `api-reference` or `example`; `tags` are use-case labels (`auth`, `mongodb`,
`webhooks`, `oauth2`, `sso`, `webauthn`, `mfa`, `magic-link`, `rate-limiting`, `redis`,
`service-mesh`, `express`, `storage-adapter`, ...). Every file also cross-links related files by
relative path.

## API reference (`api/`)

| File | Covers |
|---|---|
| [bootstrap-config.md](api/bootstrap-config.md) | `initIdentityProvider`, `configFromEnv`, full `IdpConfig` shape, event hooks |
| [errors.md](api/errors.md) | `IdpError`, `isIdpError`, the `ERROR_CODES` catalogue |
| [tokens-rs256.md](api/tokens-rs256.md) | RS256 token issuance/verification, opaque-token hashing |
| [jwks-oidc-discovery.md](api/jwks-oidc-discovery.md) | User-token JWKS, OIDC discovery document |
| [middleware.md](api/middleware.md) | `authContextMiddleware`, `serviceContextMiddleware`, `validateBody`/`validateQuery`, `cookieParser` |
| [password-email-auth.md](api/password-email-auth.md) | Register, login, refresh/logout, password reset/change, self-service profile & sessions |
| [mfa.md](api/mfa.md) | TOTP setup, confirm, disable, recovery codes, challenge verification |
| [magic-link.md](api/magic-link.md) | Passwordless email login |
| [webauthn.md](api/webauthn.md) | Passkey registration, passwordless login, passkey-as-MFA |
| [oauth2-authorization-server.md](api/oauth2-authorization-server.md) | Authorization code + PKCE, client credentials, refresh grants, client lifecycle, consent, revocation/introspection |
| [oidc.md](api/oidc.md) | UserInfo, RP-initiated logout |
| [sso-social-login.md](api/sso-social-login.md) | Google/GitHub/Microsoft/Apple/LinkedIn social login |
| [service-mesh.md](api/service-mesh.md) | Service-to-service JWKS trust and token minting/verification |
| [repository-adapters.md](api/repository-adapters.md) | The eight storage interfaces, built-in Mongo adapter, `storage.factory` pluggability |
| [cache-interface.md](api/cache-interface.md) | `CacheAdapter` contract, memory/Redis adapters, fail-closed revocation checks |
| [rate-limiter-interface.md](api/rate-limiter-interface.md) | `RateLimiter` contract, memory/Redis/noop adapters, default per-endpoint rules |
| [webhooks.md](api/webhooks.md) | `WebhookDispatcher`, `verifyWebhookSignature`, HMAC signature scheme |
| [router-and-schemas.md](api/router-and-schemas.md) | `buildRouter()`, the full mounted route table, exported zod `schemas` |

## Examples (`examples/`)

| File | Scenario |
|---|---|
| [quickstart-express.md](examples/quickstart-express.md) | Minimal runnable server |
| [register-login-refresh-logout.md](examples/register-login-refresh-logout.md) | Full password-auth session lifecycle |
| [magic-link-with-express.md](examples/magic-link-with-express.md) | Passwordless email login end-to-end |
| [mfa-totp-setup-and-verify.md](examples/mfa-totp-setup-and-verify.md) | Enable TOTP, complete an MFA-gated login |
| [webauthn-registration-and-login.md](examples/webauthn-registration-and-login.md) | Browser-side passkey registration and login |
| [custom-mongo-repository-adapter.md](examples/custom-mongo-repository-adapter.md) | Wrapping a Mongo repository, and the full `storage.factory` contract |
| [verify-hmac-webhook-signature.md](examples/verify-hmac-webhook-signature.md) | Receiving and verifying signed webhook deliveries |
| [redis-cache-adapter.md](examples/redis-cache-adapter.md) | Moving to Redis for horizontal scaling |
| [redis-rate-limiter-adapter.md](examples/redis-rate-limiter-adapter.md) | Redis-backed rate limiting, custom thresholds |
| [oauth2-authorization-code-flow.md](examples/oauth2-authorization-code-flow.md) | Client registration through PKCE token exchange |
| [sso-google-login.md](examples/sso-google-login.md) | Google social login, redirect-URI allowlisting |
| [service-mesh-s2s-tokens.md](examples/service-mesh-s2s-tokens.md) | Registering service identities, minting/verifying S2S tokens |
| [session-management.md](examples/session-management.md) | Listing/revoking sessions ("devices logged in" UI) |

## Source of truth

Written directly against the `@okeav/idp-core` source (README, `types/index.d.ts`, and every
handler/schema/config module), kept in sync as the package evolves. Where the source itself has a
notable asymmetry, gap, or non-obvious default (e.g. the SSO redirect-URI allowlist being opt-in,
or `/oauth2/token/revoke`/`/introspect` only ever operating on refresh tokens regardless of
`token_type_hint`), it's called out explicitly in the relevant file rather than silently smoothed
over — these are documented package behaviors, not documentation bugs. (As of v0.2.0: the
`/oauth2/authorize/deny` open-redirect gap and the refresh-grant scope-recompute issue that were
previously called out here have been fixed in source — see CHANGELOG.md.)
