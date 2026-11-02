---
title: "Token Issuance & Verification (RS256)"
package: "@okeav/idp-core"
category: "api-reference"
tags: ["auth", "jwt", "rs256", "tokens"]
description: "issueAccessToken, verifyAccessToken, access-token kinds, issueIdToken, issueOAuth2AccessToken, MFA challenge tokens, and opaque-token hashing."
---

# Token Issuance & Verification (RS256)

All tokens issued by this package are signed with **RS256** using the active key from
`config.signingKeys.keys` (see [Bootstrap & Config](bootstrap-config.md)). The public exports
below are thin wrappers over `src/signing/token.service.js` that inject the singleton state
internally — no internal state object leaks into the public signatures.

Signing keys are checked at `initIdentityProvider()` startup, not at the first login: every key must
be a parseable RSA key of at least 2048 bits (PEM or base64-encoded PEM) with a known `status`
(`ACTIVE`/`ROTATING`/`RETIRED`/`REVOKED`); a `privateKey`, when given, must actually pair with its
`publicKey`; and at least one `ACTIVE` (or `ROTATING`) key must carry a `privateKey` to sign with.
Any failure throws at startup.

## Access-token kinds

Every access token this package issues has `type: 'access_token'`, but they are issued to three
different parties, and verification classifies each one:

| Kind | Issued by | Distinguishing claims | `aud` |
|---|---|---|---|
| `first-party` | login, refresh, magic link, SSO, passkey login, MFA verify, and the public `issueAccessToken()` | no `client_id` | `config.issuer` (or a custom `audience`) |
| `oauth2-user` | OAuth2 `authorization_code` / `refresh_token` grants | `client_id`, `scope`; `sub` is the user | the client id |
| `oauth2-client` | OAuth2 `client_credentials` grant | `client_id`, `scope`, `gty: 'client_credentials'` (or `sub === client_id`); no user | the client id |

`verifyAccessToken` and `authContextMiddleware` accept **only `first-party`** tokens by default.
A token this IdP minted for a third-party OAuth2 client is never a credential for the IdP's own
routes — otherwise any relying party a user authorized could act as that user here (delete the
account, register a passkey, grant itself consent). A resource server that wants OAuth2 tokens
opts in with `accept` (see below) and must then check the granted scopes itself.

## `issueAccessToken(input, opts?)`

```ts
function issueAccessToken(
  input: { sub: string; email?: string; claims?: Record<string, unknown> },
  opts?: { ttlSeconds?: number; audience?: string; sessionless?: boolean; authTime?: number }
): Promise<IssuedToken>
```

`IssuedToken` is `{ token: string; expiresAt: Date; kid: string; jti: string }`.

Payload signed: `{ sub, email, claims, type: 'access_token', iss: config.issuer, aud: opts.audience ?? config.issuer, jti: crypto.randomUUID(), iat, exp }`,
plus `auth_time` when `opts.authTime` is an integer and `sessionless: true` when set. The token is
a `first-party` token (no `client_id`).

- `opts.ttlSeconds` defaults to `config.ttls.accessToken` (3600s).
- `opts.sessionless` defaults to **`true`** for this public export: a token minted here has no
  session row behind it, so it's marked `sessionless` and exempt from `authContextMiddleware`'s
  per-request session check (`session.verifyOnEachRequest` — see [Middleware](middleware.md)),
  which would otherwise reject it as `TOKEN_REVOKED`. It also means logout-all/password reset can't
  revoke it before `exp`. Pass `{ sessionless: false }` only if you created a session row with this
  token's `jti` yourself.
- `opts.audience` changes `aud`. A token with a non-issuer audience is refused by
  `verifyAccessToken`/`authContextMiddleware` unless they're given the same `audience` option.
- `opts.authTime` (Unix seconds) becomes the `auth_time` claim — when the user last actually
  authenticated. [`requireRecentAuth()`](middleware.md#requirerecentauthopts) reads it; a token
  without it never counts as a recent login.
- Throws `MISSING_REQUIRED_FIELDS` (400) if `sub` is omitted.
- `loginHandler`, `verifyMagicLinkHandler`, `verifyAuthenticationHandler` (WebAuthn), MFA verify,
  refresh, and the SSO callback all sign through the same underlying function via `issueSession()`
  — there is no separate, weaker token-issuance path for any login method. Those tokens are
  session-bound (never `sessionless`) and carry `auth_time`: the time of the actual login, copied
  unchanged onto every token a refresh mints, so a refreshed session never looks like a fresh login.

## `verifyAccessToken(token, opts?)`

```ts
function verifyAccessToken(token: string, opts?: {
  issuer?: string;                 // default: config.issuer
  audience?: string | string[];    // the aud a first-party token must carry; default: config.issuer
  accept?: Array<'first-party' | 'oauth2-user' | 'oauth2-client'>; // default: ['first-party']
}): Promise<AccessTokenClaims>
```

Verifies the signature (by the token's `kid`; if the `kid` is missing or unknown, every
`ACTIVE`/`ROTATING` key is tried — a `REVOKED` key never verifies), `iss`, `exp` (30-second
`clockTolerance`), `type === 'access_token'`, the token's [kind](#access-token-kinds) against
`accept`, and its audience: a `first-party` token's `aud` must be one of `audience` (default the
issuer); an OAuth2 token's `aud` must equal its own `client_id`. Returns the decoded payload.

```js
// A resource server that also accepts OAuth2 user tokens — it must then check scopes itself:
const claims = await verifyAccessToken(token, { accept: ['first-party', 'oauth2-user'] });
if (claims.client_id && !claims.scope.split(' ').includes('orders:read')) {
  throw new Error('insufficient scope');
}
```

> **It does not check revocation.** `verifyAccessToken` is a stateless signature check: a token
> whose session was logged out, revoked, or ended by logout-all / password reset still verifies
> until `exp`. A resource server that must refuse revoked sessions should use
> [`authContextMiddleware`](middleware.md), which also checks the session store
> (`session.verifyOnEachRequest`).

Throws:
- `TOKEN_EXPIRED` (401) if `exp` has passed.
- `INVALID_TOKEN` (401) for any other verification failure (bad signature, unknown `kid` across
  every verifiable key, wrong issuer or `type`, a token kind not in `accept`, or the wrong
  audience).

## `issueIdToken(user, audience, nonce?, opts?)`

```ts
function issueIdToken(
  user: IdentityUser,
  audience: string,
  nonce?: string,
  opts?: { scopes?: string[]; authTime?: number; ttlSeconds?: number }
): Promise<IssuedToken>
```

Builds an OIDC ID token. Always present: `sub` (stringified user id), `aud` and `azp` (both
`audience`), `iss`, `jti`, `iat`, `exp`. User claims follow `opts.scopes` (OIDC Core §5.4):

- `email` scope → `email`, `email_verified` (`status !== 'PENDING_VERIFICATION'`).
- `profile` scope → `name` (`displayName`, else first + last name), `given_name`, `family_name`,
  `picture` (`avatarUrl`), `locale`, `zoneinfo` from `user.profile` (omitted if falsy — not sent
  as `null`/`undefined`).

`opts.scopes` defaults to `['openid', 'email', 'profile']` (every claim) for this public export.
`opts.authTime` (Unix seconds) becomes `auth_time`; `nonce`, if provided, is echoed. `exp` is
`opts.ttlSeconds` or `config.ttls.idToken` (default 3600s).

The OAuth2/OIDC token endpoint calls it with the scopes actually granted, the `nonce` sent to
`/oauth2/authorize` (stored with the code — a `nonce` at the token endpoint is ignored), the
login's `auth_time`, and the client's `idTokenTTL` — see [OIDC](oidc.md).

## `issueOAuth2AccessToken(subject, client, scopes, opts?)`

```ts
function issueOAuth2AccessToken(
  subject: { id: string },
  client: { clientId: string; accessTokenTTL?: number },
  scopes: string[],
  opts?: { sessionless?: boolean } // default true for this public export — see issueAccessToken above
): Promise<IssuedToken>
```

Issues an access token for the OAuth2 authorization-server flows (see
[OAuth2 Authorization Server](oauth2-authorization-server.md)). TTL is `client.accessTokenTTL ||
config.ttls.accessToken`. The signed payload carries **both** top-level `scope`/`client_id`
(RFC 6749/7519 convention, for resource servers reading raw JWT claims) **and** a nested
`claims: { scope, clientId }` with `type: 'access_token'`, so it verifies through the same
`verifyAccessToken`/`authContextMiddleware` code path as first-party tokens.

`aud` is `client.clientId` and the token carries `client_id`, so it classifies as `oauth2-user` —
or `oauth2-client` when `subject.id === client.clientId` — and is therefore refused by the default
`verifyAccessToken`/`authContextMiddleware` (see [Access-token kinds](#access-token-kinds)). It
carries no `auth_time`.

The token endpoint's `authorization_code`/`refresh_token` grants create a session row (`kind:
'oauth2'`) with the token's `jti` (session-bound, revocable — also by consent revocation, client
deactivation and token revocation). The `client_credentials` grant has none: its token is
`sessionless`, has the client id as `sub`, and is marked `gty: 'client_credentials'`.

## `issueMfaChallengeToken(subjectId)` / `verifyMfaChallengeToken(token)`

```ts
function issueMfaChallengeToken(subjectId: string): Promise<string>
function verifyMfaChallengeToken(token: string): { sub: string; type: 'mfa_challenge' }
```

A short-lived (`config.ttls.mfaChallenge`, default 300s), single-purpose RS256 token identifying
which user just passed the first authentication factor and still owes a second one. Issued by
`loginHandler`, `verifyMagicLinkHandler` and the SSO callback when `user.mfaEnabled`; consumed by
`verifyMfaChallengeHandler` (TOTP), `generateMfaWebauthnChallengeOptionsHandler`, and
`verifyMfaWebauthnChallengeHandler` (WebAuthn MFA). `verifyMfaChallengeToken` is synchronous,
checks only signature, expiry and `type`, and throws `INVALID_MFA_CHALLENGE_TOKEN` (401).

The built-in MFA handlers add two checks on top: a challenge token completes **one** login only
(its `jti` is spent atomically once the second factor checks out), and a token issued before the
account's last password change is void. Calling `verifyMfaChallengeToken` yourself gives you
neither.

## `verifyIssuedToken(token, opts?)`

```ts
function verifyIssuedToken(token: string, opts?: { issuer?: string }): Record<string, unknown> | null
```

Generic "did we issue this" check — tries every verifiable key, returns the decoded payload on
success or **`null`** on any failure (never throws). It accepts any token this IdP signed and
checks neither `type`, audience nor kind, so don't use it to authenticate a request.
`endSessionHandler` uses it internally for the `id_token_hint` (accepting expired hints, per the
spec) and then insists the hint is an ID token.

## Opaque-token hashing

Refresh tokens, password-reset tokens, email-verification tokens, and magic-link tokens are
**not** JWTs — they're random opaque strings, hashed at rest with HMAC-SHA256 keyed by
`config.security.tokenHashSecret` (at least 32 characters, checked at startup), so a database read
alone can't be used to forge a valid token.

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
- [Middleware](middleware.md) — `authContextMiddleware` wraps `verifyAccessToken` and adds the
  revocation check; `requireRecentAuth()` reads `auth_time`.
- [Password & Email Auth](password-email-auth.md) — the primary consumer of `issueAccessToken`
  via the shared `issueSession()` helper.
- [Service Mesh](service-mesh.md) — a parallel, separately-keyed RS256 token system for
  service-to-service calls (`mintServiceToken`), not related to user tokens.
