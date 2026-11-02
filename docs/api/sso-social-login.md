---
title: "SSO / Social Login"
package: "@okeav/idp-core"
category: "api-reference"
tags: ["auth", "sso", "oauth2", "social-login"]
description: "Single-step SSO callback for Google, GitHub, Microsoft, Apple, and LinkedIn — browser-bound state, PKCE/nonce, verified-email account linking, and the MFA hand-off."
---

# SSO / Social Login

Google, GitHub, Microsoft (Entra ID), Apple, and LinkedIn. Configure whichever you use under
`config.oauthProviders.<name>` — a provider only appears in the internal provider table (and is
therefore usable) if its `clientId` is set; otherwise `/sso/<name>` throws `INVALID_SSO_PROVIDER`.

## Required configuration

As soon as any provider has a `clientId`, `initIdentityProvider()` **refuses to start** without:

```js
sso: {
  // Absolute https URL (http only for localhost, or with NODE_ENV=development) providers redirect back to: <baseCallbackUrl>/sso/<provider>/callback.
  // Use the URL the router is mounted at, e.g. 'https://api.example.com/auth'.
  baseCallbackUrl: 'https://api.example.com/auth',
  // Exact origins (scheme://host[:port], no path) SSO may send the browser back to.
  allowedRedirectOrigins: ['https://app.example.com'],
  providerTimeoutMs: 10000, // optional — per provider call (token exchange, userinfo). Default 10000.
},
```

With `configFromEnv`: `IDP_SSO_BASE_CALLBACK_URL`, `IDP_SSO_ALLOWED_REDIRECT_ORIGINS`
(comma-separated). There is no "allow everything" mode — a `redirect_uri` is accepted only if its
origin is on the list **and** it is `https` (or `http` to `localhost`/`127.0.0.1`/`[::1]`) with no
credentials in it.

**Mount `cookie-parser` before the router** (`app.use(cookieParser())` — the package re-exports
it): the callback reads a per-login binding cookie and refuses to complete without it (see below).

## Provider reference

| Provider | Scopes | Config fields | Binding | Email trusted for linking when… |
|---|---|---|---|---|
| `google` | `openid email profile` | `clientId, clientSecret` | PKCE (S256) | `email_verified` is true |
| `github` | `read:user user:email` | `clientId, clientSecret` | PKCE (S256) | always the account's **primary verified** address (see below) |
| `microsoft` | `openid email profile User.Read` | `clientId, clientSecret, tenant?, trustEmail?` | PKCE (S256) | `tenant` names a single tenant, or `trustEmail: true` |
| `apple` | `openid email name` | `clientId, teamId, keyId, privateKeyPem` (no static secret — see below) | `nonce` in the `id_token` | `email_verified` is true |
| `linkedin` | `openid profile email` | `clientId, clientSecret` | `state` + binding cookie only | `email_verified` is true |

**GitHub**: the profile's public `email` is never used (it carries no verification status). The
handler always reads `/user/emails` and takes the entry with `primary === true && verified ===
true`; with none, there is no email at all (→ `error=email_required`).

**Microsoft**: `email` is Graph's `mail`, falling back to `userPrincipalName` when `mail` is null.
Microsoft doesn't verify either — they're set by whichever tenant's admin owns the account — so
with a multi-tenant authority (`tenant` unset/`'common'`, `'organizations'`, `'consumers'`) anyone
can create a tenant and give a user `mail = victim@yourcompany.com` ("nOAuth"). The address is
therefore trusted only when `tenant` is pinned to one tenant (your tenant GUID or domain), or with
an explicit `trustEmail: true` (`IDP_SSO_MICROSOFT_TRUST_EMAIL`) if you accept that risk. Without
either, a Microsoft identity **can't create or link an account by email** — new users can't sign
up through Microsoft on the `common` authority; identities already linked keep working.

**Apple**: has no UserInfo endpoint — identity comes from the **ID token payload** returned by
Apple's token endpoint. Its signature isn't verified (it arrives over TLS straight from Apple in
exchange for this server's client-authenticated code request, which OIDC Core §3.1.3.7 accepts),
but its claims are: `iss` must be `https://appleid.apple.com`, `aud` must include your
`clientId`, it must not be expired, and its `nonce` must be the one this login sent. Any mismatch
→ 400 `SSO_PROVIDER_ERROR`. Apple sends `email_verified` as the string `"true"`, which counts.
Apple only sends the `user` field (name) on the account's **first** authorization ever —
subsequent logins won't include it.

**Apple client secret**: generated fresh on every code exchange, as an ES256 JWT signed with
`privateKeyPem` (`iss: teamId, aud: 'https://appleid.apple.com', sub: clientId`) that **lives 5
minutes** — it only has to outlive one request, so a secret leaked from a log is useless almost
immediately. Unrelated to this package's own RS256 signing keys.

**Provider calls** (code exchange, userinfo, GitHub's emails) time out after
`config.sso.providerTimeoutMs` (default 10 s) and **don't follow redirects**.

## `GET /sso/:provider` — `initiateSsoHandler`

**Rate limited** per IP, fail-closed: `sso-initiate:ip:<ip>` against
`config.rateLimiting.ssoInitiate` (default 30 per 5 minutes) — each call parks a state entry in
the cache. 429 `RATE_LIMIT_EXCEEDED` / 503 `RATE_LIMITER_UNAVAILABLE`.

Query: `redirect_uri` (required — the **consumer's own** post-login redirect target, not the OAuth
provider's callback URL; must pass the allowlist above), plus any other query params, which are
captured into an `extra` bag and handed back to `resolveAuthContext`'s `ctx.extra` at callback
time — never interpreted by this package. Only short string values are kept: at most 10 keys,
keys ≤ 64 and values ≤ 256 characters; anything else (nested objects from Express 4's query
parser, long values) is dropped. **They come from whoever built the link — treat them as
untrusted** and never grant anything on them alone.

Generates a random `state` (32 bytes, base64url) and a random **binding** value, and stores
`{ provider, redirect_uri, extra, bindingHash, codeVerifier, nonce }` in the cache keyed by the
state (`config.ttls.ssoState`, default 600s). Sets the binding in an httpOnly cookie named
`__Host-idp_sso_<first 16 chars of state>` (plain `idp_sso_…` only when cookies aren't Secure; one
per attempt, so two logins in two tabs don't collide; `SameSite=Lax`, or `SameSite=None; Secure`
for Apple, whose callback is a cross-site form POST). It is **always host-only** (`Path=/`, no
`Domain` — `cookies.domain` does not apply since 0.4.0): it only has to come back to the IdP, and a
binding cookie planted from a sibling subdomain would bind the victim's browser to the attacker's
login attempt. A callback carrying the binding cookie twice is refused (400 `COOKIE_CONFLICT`). Then redirects to the provider's authorization URL with
`response_type=code`, the package's **own** callback URL (not your `redirect_uri`) as
`redirect_uri`, `code_challenge` + `code_challenge_method=S256` (Google, GitHub, Microsoft), `nonce`
(Apple), and provider-specific extras: Apple gets `response_mode=form_post`; Google gets
`access_type=online` (so **Google will not issue a refresh token** to this flow) and
`prompt=select_account`.

Errors: `RATE_LIMIT_EXCEEDED` (429) / `RATE_LIMITER_UNAVAILABLE` (503); `INVALID_REDIRECT_URI`
(400, missing or not allowed — checked before the provider); `INVALID_SSO_PROVIDER` (400,
unknown/unconfigured provider).

Hooks: `auditLog('SSO_INITIATED', { provider })`, fired right before the redirect to the provider.

## `GET|POST /sso/:provider/callback` — `ssoCallbackHandler`

Reads `code`/`state`/`error` from query (GET, most providers) or body (POST, Apple's
`form_post` callback — `buildRouter()` mounts `express.urlencoded()` on the POST route for this).
Only string values are read.

**Genuinely single-step**: resolves identity, calls `resolveAuthContext`, mints the full session —
all in one handler invocation, no intermediate exchange token issued to the client.

Steps:

1. **State and binding, before anything else** — including a provider `error`, so nothing on this
   endpoint answers a request this browser didn't start. The state entry is consumed atomically
   (`cache.take()`), whatever happens next; a missing/expired state or one minted for another
   provider → 400 `INVALID_SSO_STATE`. The binding cookie is cleared and must hash to the stored
   value — a callback completed in a different browser (login CSRF: an attacker starting a login
   with their own provider account and getting a victim's browser to finish it) → 400
   `INVALID_SSO_STATE`.
2. **Provider error** → redirect to `redirect_uri?error=provider_error&provider_error=<code>` (the
   provider's error code reduced to letters/underscores, ≤ 64 chars; its free-text description is
   never reflected). No `code` → `?error=provider_error`.
3. **Code exchange** (with the PKCE `code_verifier`), then profile fetch/normalize (Apple: the
   `id_token` checks above).
4. **No email** → redirect `?error=email_required`.
5. **Account resolution**:
   - An identity already linked (`findByExternalProvider(provider, providerId)`) logs in by
     provider id — its email isn't consulted.
   - Otherwise the provider must **assert the email is verified** (per the table above); if not →
     redirect `?error=email_not_verified`. Then, by email:
     - an `ACTIVE` account → the identity is linked to it (`isNewLink`). A failed-password lockout
       doesn't change that (it locks password login only, and stays in place — another method
       signing in doesn't reset the password-guessing budget; a pre-0.4.0 row with status `LOCKED`
       and a `lockUntil` counts as `ACTIVE`, and the SSO login clears that legacy lock);
     - a `PENDING_VERIFICATION` account (registered here, never verified) → claimed: activated,
       with any password and MFA state set before the address was proven **discarded** and
       outstanding email-verification codes deleted, then linked (audit
       `SSO_PENDING_ACCOUNT_CLAIMED`). The activation is conditional on the account still being
       pending (`updateByIdIfStatus`): if its owner activated it meanwhile, nothing is wiped and the
       identity is just linked. The owner can set a password through password reset;
     - any other status (administratively locked, suspended, deleted …) → a login method is
       **never attached**;
       redirect `?error=account_inactive`;
     - no account → a new one is created with `status: 'ACTIVE'` directly (the provider verified
       the address) (`isNewUser`).
6. **Status gate**: a matched user that isn't `ACTIVE` → redirect `?error=account_inactive`.
7. **MFA**: SSO is one factor. If the account has MFA enabled, **no session is issued and no
   session cookies are set**; the browser is redirected to `redirect_uri` with the challenge in
   the URL **fragment** (which never reaches a server log or a `Referer` header):

   ```
   https://app.example.com/after-login#mfa_required=1&mfa_challenge_token=<jwt>&expires_in=300
   ```

   Your frontend reads `location.hash` and completes the login at `POST /mfa/verify` (or
   `POST /webauthn/mfa/verify`) with `mfaChallengeToken` — see [MFA](mfa.md). Audit event
   `SSO_MFA_REQUIRED`. The session then comes from `/mfa/verify`, whose `resolveAuthContext` call
   is `{ isNewUser: false, method: 'mfa' }` — `provider` and `extra` aren't passed through.
8. Otherwise: `resolveAuthContext` → `issueSession` → session cookies → redirect to
   `redirect_uri?ssoLogin=success`.

> **Redirect outcomes are part of the callback's public contract** — they're written directly, not
> passed to your error middleware: `?error=provider_error` (plus `provider_error`),
> `?error=email_required`, `?error=email_not_verified`, `?error=account_inactive`, the
> `#mfa_required=1&…` fragment, and `?ssoLogin=success`. Params are added to whatever query string
> `redirect_uri` already has.

**Errors thrown as `IdpError`**: `INVALID_SSO_STATE` (400 — missing/expired/used state, wrong
provider, or missing/mismatched binding cookie); `INVALID_SSO_PROVIDER` (400, provider config
missing at callback time, e.g. removed after initiate started); `SSO_PROVIDER_ERROR` (400, Apple
`id_token` not issued for this login).

> **Provider-communication failures are plain `Error`, not `IdpError`** — code-exchange and
> profile-fetch failures (non-2xx, timeouts, redirects), and incomplete Apple config, throw bare
> `Error`s with no `.code`/`.httpStatus`. Mount `idpErrorHandler()` after the router: it answers
> those `500 { error: 'INTERNAL_ERROR' }` (logged, no internals) — see [Errors](errors.md).

Hooks: `auditLog('SSO_REGISTERED', ...)` (new user) and/or `auditLog('SSO_PROVIDER_LINKED', ...)`
(existing user linked by email), then `auditLog('SSO_MFA_REQUIRED', ...)` or
`auditLog('SSO_LOGIN', { userId, provider })`. On the session path,
`resolveAuthContext(user, { isNewUser, isNewLink, provider, extra })`.

## Related

- [Password & Email Auth](password-email-auth.md) — shared `issueSession`/cookie mechanics.
- [MFA](mfa.md) — completing the `mfa_required` challenge.
- [Bootstrap & Config](bootstrap-config.md) — `config.oauthProviders`, `config.sso`, the
  `IDP_SSO_*` variables.
- [SSO Google Login example](../examples/sso-google-login.md)
