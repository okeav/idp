---
title: "Token Issuance & Verification (RS256)"
package: "@okeav/idp-core"
category: "api-reference"
tags: ["auth", "jwt", "rs256", "tokens"]
description: "issueAccessToken, verifyAccessToken, issueIdToken, issueOAuth2AccessToken, MFA challenge tokens, and opaque-token hashing."
---

# Token Issuance & Verification (RS256)

All tokens issued by this package are signed with **RS256** using the active key from
`config.signingKeys.keys` (see [Bootstrap & Config](bootstrap-config.md)). The public exports
below are thin wrappers over `src/signing/token.service.js` that inject the singleton state
internally — no internal state object leaks into the public signatures.

## `issueAccessToken(input, opts?)`

```ts
function issueAccessToken(
  input: { sub: string; email?: string; claims?: Record<string, unknown> },
  opts?: { ttlSeconds?: number; audience?: string }
): Promise<IssuedToken>
```

`IssuedToken` is `{ token: string; expiresAt: Date; kid: string; jti: string }`.

Payload signed: `{ sub, email, claims, type: 'access_token', iss: config.issuer, aud: opts.audience ?? config.issuer, jti: crypto.randomUUID(), iat, exp }`.

- `opts.ttlSeconds` defaults to `config.ttls.accessToken` (3600s).
- Throws `MISSING_REQUIRED_FIELDS` (400) if `sub` is omitted.
- This is the same function `loginHandler`, `verifyMagicLinkHandler`, `verifyAuthenticationHandler`
  (WebAuthn), and SSO callback all call internally via `issueSession()` — there is no separate,
  weaker token-issuance path for any login method.

## `verifyAccessToken(token, opts?)`

```ts
function verifyAccessToken(token: string, opts?: { issuer?: string }): Promise<AccessTokenClaims>
```

Verifies signature (trying every `ACTIVE`/`ROTATING` key if the token's `kid` header doesn't
match a known key — a 30-second `clockTolerance` is applied), checks `type === 'access_token'`,
and returns the decoded payload. This is what `authContextMiddleware` calls internally — see
[Middleware](middleware.md).

Throws:
- `TOKEN_EXPIRED` (401) if `exp` has passed.
- `INVALID_TOKEN` (401) for any other verification failure (bad signature, unknown `kid` across
  every verifiable key, wrong `type`).

## `issueIdToken(user, audience, nonce?)`

```ts
function issueIdToken(user: IdentityUser, audience: string, nonce?: string): Promise<IssuedToken>
```

Builds an OIDC ID token: `sub` (stringified user id), `email`, `email_verified` (`status !==
'PENDING_VERIFICATION'`), `name`/`given_name`/`family_name`/`picture`/`locale`/`zoneinfo` from
`user.profile` (omitted if falsy — not sent as `null`/`undefined`), `aud`, `iss`, `jti`, `iat`,
`exp` (`config.ttls.idToken`, default 3600s), and `nonce` if provided. Used by the OAuth2/OIDC
token endpoint — see [OIDC](oidc.md).

## `issueOAuth2AccessToken(subject, client, scopes)`

```ts
function issueOAuth2AccessToken(
  subject: { id: string },
  client: { clientId: string; accessTokenTTL?: number },
  scopes: string[]
): Promise<IssuedToken>
```

Issues an access token for the OAuth2 authorization-server flows (see
[OAuth2 Authorization Server](oauth2-authorization-server.md)). TTL is `client.accessTokenTTL ||
config.ttls.accessToken`. The signed payload carries **both** top-level `scope`/`client_id`
(RFC 6749/7519 convention, for resource servers reading raw JWT claims) **and** a nested
`claims: { scope, clientId }` with `type: 'access_token'` — the nesting exists so an OAuth2-issued
token verifies through the exact same `verifyAccessToken`/`authContextMiddleware` path as
password- and SSO-issued tokens, all of which require `type: 'access_token'`; a flat
OAuth2-only claim set would otherwise lack that field.

## `issueMfaChallengeToken(subjectId)` / `verifyMfaChallengeToken(token)`

```ts
function issueMfaChallengeToken(subjectId: string): Promise<string>
function verifyMfaChallengeToken(token: string): { sub: string; type: 'mfa_challenge' }
```

A short-lived (`config.ttls.mfaChallenge`, default 300s), single-purpose RS256 token identifying
which user just passed the first authentication factor and still owes a second one. Issued by
`loginHandler` when `user.mfaEnabled`; consumed by `verifyMfaChallengeHandler` (TOTP),
`generateMfaWebauthnChallengeOptionsHandler`, and `verifyMfaWebauthnChallengeHandler` (WebAuthn
MFA). `verifyMfaChallengeToken` is synchronous and throws `INVALID_MFA_CHALLENGE_TOKEN` (401) —
unlike `verifyAccessToken`, it does **not** check the revocation cache (challenge tokens are
short-lived and single-purpose by construction, not revocable sessions).

## `verifyIssuedToken(token, opts?)`

```ts
function verifyIssuedToken(token: string, opts?: { issuer?: string }): Record<string, unknown> | null
```

Generic "did we issue this" check — tries every verifiable key, returns the decoded payload on
success or **`null`** on any failure (never throws). Used internally by `endSessionHandler` to
validate an OIDC `id_token_hint` where a hard failure shouldn't block logout.

## Opaque-token hashing

Refresh tokens, password-reset tokens, email-verification tokens, and magic-link tokens are
**not** JWTs — they're random opaque strings, hashed at rest with HMAC-SHA256 keyed by
`config.security.tokenHashSecret`, so a database read alone can't be used to forge a valid token.

```js
// internal, not exported on the public surface — documented for context on
// what SessionRepository/VerificationTokenRepository store
hashOpaqueToken(state, rawToken) // => hex HMAC-SHA256
generateOpaqueToken(byteLength = 64) // => crypto.randomBytes(byteLength).toString('hex')
```

Magic-link and password-reset/email-verification tokens use `generateOpaqueToken(32)` (32 raw
bytes → 64 hex chars); refresh tokens use the 64-byte default.

## Related

- [JWKS & OIDC Discovery](jwks-oidc-discovery.md) — how these signing keys are published for
  external verification.
- [Middleware](middleware.md) — `authContextMiddleware` wraps `verifyAccessToken`.
- [Password & Email Auth](password-email-auth.md) — the primary consumer of `issueAccessToken`
  via the shared `issueSession()` helper.
- [Service Mesh](service-mesh.md) — a parallel, separately-keyed RS256 token system for
  service-to-service calls (`mintServiceToken`), not related to user tokens.
