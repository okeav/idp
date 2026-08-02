---
title: "SSO / Social Login"
package: "@okeav/idp-core"
category: "api-reference"
tags: ["auth", "sso", "oauth2", "social-login"]
description: "Single-step SSO callback for Google, GitHub, Microsoft, Apple, and LinkedIn — CSRF state, profile normalization, and account linking."
---

# SSO / Social Login

Google, GitHub, Microsoft (Entra ID), Apple, and LinkedIn. Configure whichever you use under
`config.oauthProviders.<name>` — a provider only appears in the internal provider table (and is
therefore usable) if its `clientId` is set; otherwise `/sso/<name>` throws `INVALID_SSO_PROVIDER`.

## Provider reference

| Provider | Scopes | Config fields |
|---|---|---|
| `google` | `openid email profile` | `clientId, clientSecret` |
| `github` | `read:user user:email` | `clientId, clientSecret` |
| `microsoft` | `openid email profile User.Read` | `clientId, clientSecret, tenant?` (default `'common'` — the Microsoft multi-tenant endpoint accepting both work/school and personal accounts; set to a tenant GUID or `organizations` to restrict) |
| `apple` | `openid email name` | `clientId, teamId, keyId, privateKeyPem` (no static secret — see below) |
| `linkedin` | `openid profile email` | `clientId, clientSecret` |

**GitHub**: if the `/user` response has no public email, falls back to `/user/emails` and picks
the entry with `primary === true && verified === true`.

**Microsoft**: `email` falls back to `userPrincipalName` when `mail` is null (common for accounts
without an Exchange mailbox).

**Apple**: has no UserInfo endpoint — identity comes from decoding the **ID token payload**
directly (`decodeJwtPayload`, a base64url JSON decode with **no signature verification** — trust
rests on the token having just been received directly from Apple's token endpoint over TLS in the
same request). Apple only sends the `user` field (name/email) on the account's **first**
authorization ever — subsequent logins won't include it.

**Apple client secret**: generated fresh on every code exchange (not cached), as an ES256 JWT
signed with `privateKeyPem` (`iss: teamId, aud: 'https://appleid.apple.com', sub: clientId`, 6-month
max lifetime per Apple's requirement) — unrelated to and independent of this package's own RS256
signing keys.

## `GET /sso/:provider` — `initiateSsoHandler`

Query: `redirect_uri` (required, must be a URL — the **consumer's own** post-login redirect target,
not the OAuth provider's callback URL), plus any other query params, which are captured verbatim
into an `extra` bag and handed back to `resolveAuthContext`'s `ctx.extra` at callback time —
never interpreted by this package.

> **Redirect-URI allowlisting is opt-in, not opt-out.** If `config.sso.allowedRedirectOrigins` is
> unset or empty, **every** `redirect_uri` is accepted — there is no open-redirect protection on
> this parameter by default. Set `allowedRedirectOrigins` (an array of allowed origins, exact
> scheme+host+port match, no wildcard/subdomain support) in any deployment where this matters.

Generates a CSRF `state` (20 random bytes, hex), stores `{ provider, redirect_uri, extra }` in the
cache keyed by it (`config.ttls.ssoState`, default 600s), and redirects to the provider's
authorization URL. `response_type=code`, the package's **own** callback URL (not your
`redirect_uri`) as `redirect_uri`, and provider-specific extras: Apple gets `response_mode=
form_post`; Google gets `access_type=online` (so **Google will not issue a refresh token** to
this flow) and `prompt=select_account`.

Errors: `INVALID_REDIRECT_URI` (400, missing or not on an allowed origin);
`INVALID_SSO_PROVIDER` (400, unknown/unconfigured provider).

Hooks: `auditLog('SSO_INITIATED', { provider })`, fired right before the redirect to the provider.

> `config.sso.baseCallbackUrl` is effectively **mandatory in practice** even though nothing at
> config-validation time enforces it — if unset, the constructed callback URL is relative
> (`/sso/google/callback`), which real OAuth providers will reject since they require absolute
> redirect URIs.

## `GET|POST /sso/:provider/callback` — `ssoCallbackHandler`

Reads `code`/`state`/`error` from query (GET, most providers) or body (POST, Apple's
`form_post` callback — `buildRouter()` mounts `express.urlencoded()` on the POST route for this).

Confirmed **genuinely single-step**, matching the README: resolves identity, calls
`resolveAuthContext`, mints the full session — all in one handler invocation, no intermediate
exchange token issued to the client. (An earlier two-step design existed only because identity and
role resolution lived in two separate internal Okeav services — not for any CSRF/security reason;
the CSRF-relevant `state` check happens before any token is minted regardless.)

Steps: provider-error check → CSRF state lookup+delete (single-use) → code exchange → profile
fetch/normalize → find-by-external-provider, else find-by-email-and-link, else create → status
gate → `resolveAuthContext` → `issueSession` → cookies → redirect.

**New-user SSO signups get `status: 'ACTIVE'` directly** (skipping `PENDING_VERIFICATION`) — the
provider is treated as having already verified the email.

> **Three outcomes deliberately bypass the `IdpError`/`next(err)` pattern** and write the response
> directly — treat these as part of the callback's public contract, not exceptions your error
> middleware will ever see:
> - Provider returned an OAuth error → `400 { error, error_description }` (JSON, not a redirect).
> - No email in the normalized profile → redirects to your `redirect_uri` with
>   `?error=email_required`.
> - Matched user's status isn't `ACTIVE` (e.g. `LOCKED`/`SUSPENDED`, linking via SSO doesn't bypass
>   this) → redirects with `?error=account_inactive`.
>
> On success, redirects to `redirect_uri?ssoLogin=success`.

**Errors thrown as `IdpError`**: `INVALID_SSO_STATE` (400, missing/expired/mismatched-provider
state); `INVALID_SSO_PROVIDER` (400, provider config missing at callback time, e.g. removed after
initiate started).

> **The cached state entry is only deleted after it passes validation, not "regardless of
> outcome."** `callback.controller.js` reads the state, and only calls `cache.del()` once it's
> confirmed to exist *and* match the requested provider. If the state exists but was minted for a
> different provider (provider-mismatch case), the `INVALID_SSO_STATE` error is thrown **before**
> the delete — that entry is left in the cache and simply expires naturally at its
> `ttls.ssoState` TTL rather than being consumed immediately. A genuinely single-use state (right
> provider, successfully consumed) is deleted right after the read, before the rest of the callback
> runs — so replay protection holds for the success path; it's specifically the mismatched-provider
> rejection that doesn't clean up early.

> **Provider-communication failures are plain `Error`, not `IdpError`** — code exchange and
> profile-fetch failures (non-2xx from the provider), an unrecognized provider name, and
> incomplete Apple config all throw bare `Error` objects with no `.code`/`.httpStatus`. An
> `IdpError`-aware error-handling middleware will fall through to its generic/500 path for these —
> worth a defensive `instanceof Error` catch-all in your handler regardless of `isIdpError()`.

Hooks: `auditLog('SSO_REGISTERED', ...)` (new user) and/or `auditLog('SSO_PROVIDER_LINKED', ...)`
(existing user linked by email), then always `auditLog('SSO_LOGIN', { userId, provider })`.
`resolveAuthContext(user, { isNewUser, isNewLink, provider, extra })`.

## Related

- [Password & Email Auth](password-email-auth.md) — shared `issueSession`/cookie mechanics.
- [Bootstrap & Config](bootstrap-config.md) — `config.oauthProviders`, `config.sso`.
- [SSO Google Login example](../examples/sso-google-login.md)
