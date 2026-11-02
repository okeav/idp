---
title: "Social Login with Google"
package: "@okeav/idp-core"
category: "example"
tags: ["auth", "sso", "oauth2", "google"]
description: "Configure the Google SSO provider and wire the initiate/callback redirect flow, including the required redirect-URI allowlist and the MFA hand-off."
---

# Social Login with Google

The same `initiate` → provider → `callback` pattern works for Google, GitHub, Microsoft, Apple,
and LinkedIn — see [SSO / Social Login](../api/sso-social-login.md) for provider-specific details
(Apple and Microsoft need extra config; Microsoft on the default `common` authority can't create or
link accounts by email).

## Prerequisites

- A Google OAuth 2.0 Client ID/Secret (Google Cloud Console → APIs & Services → Credentials).
- Google's authorized redirect URI set to this package's own callback endpoint, **not** your
  frontend's post-login page. The exact path depends on both `config.sso.baseCallbackUrl` and
  wherever you mount `buildRouter()` — see the note under Config below. In this example
  (`buildRouter()` mounted at `/auth`, as in the "Mount the router" section), that's
  `<your issuer>/auth/sso/google/callback`.

## Config

```js
await initIdentityProvider({
  issuer: 'https://idp.example.com',
  // ...

  oauthProviders: {
    google: {
      clientId: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    },
  },

  // Both fields are REQUIRED once any provider is configured — initIdentityProvider() refuses to
  // start without them.
  sso: {
    // Absolute URL the package builds the provider callback from:
    // `baseCallbackUrl + '/sso/<provider>/callback'`, nothing more. This package has zero awareness
    // of where you mount buildRouter() — if you mount it under a prefix (this example mounts it at
    // `/auth`, matching the Quickstart), that prefix must be part of baseCallbackUrl, or Google
    // will be sent a redirect_uri your server never actually serves.
    baseCallbackUrl: 'https://idp.example.com/auth',

    // Exact origins (scheme://host[:port]) /sso/:provider may send the browser back to. https only
    // (http is allowed for localhost). Any other redirect_uri is refused with INVALID_REDIRECT_URI.
    allowedRedirectOrigins: ['https://app.example.com'],
  },

  hooks: {
    resolveAuthContext: async (user, ctx) => {
      // ctx = { isNewUser, isNewLink, provider: 'google', extra }
      // `extra` carries the short string query params your frontend appended to the initiate URL
      // beyond `redirect_uri`. Anyone can build that URL, so treat them as untrusted hints —
      // never grant a role or permission because `extra` asked for it.
      return { claims: { role: 'member' } };
    },
  },
});
```

## Mount the router

```js
import express from 'express';
import { buildRouter, cookieParser, idpErrorHandler } from '@okeav/idp-core';

const app = express();
app.use(cookieParser()); // BEFORE the router — the SSO callback needs its binding cookie
app.use(express.json());
app.use('/auth', buildRouter());
app.use(idpErrorHandler()); // after the router
```

`GET /auth/sso/google` sets a short-lived httpOnly binding cookie, and the callback completes only
in the browser that carries it — so a login started by someone else can't be finished in your
user's browser. Without `cookieParser()` every callback fails with `INVALID_SSO_STATE`.

## Start the flow

```js
function startGoogleLogin() {
  const url = new URL('https://idp.example.com/auth/sso/google');
  url.searchParams.set('redirect_uri', 'https://app.example.com/post-login');
  // Extra params (up to 10 short strings) are handed back to resolveAuthContext's ctx.extra:
  url.searchParams.set('returnTo', '/settings');
  window.location.href = url.toString();
}
```

This redirects the browser to `/auth/sso/google`, which itself redirects to Google's consent
screen (with PKCE), which redirects back to `<issuer>/auth/sso/google/callback` (matching
`baseCallbackUrl` above), which (on success) redirects the browser to
`https://app.example.com/post-login?ssoLogin=success` with the session cookies already set.
`/sso/:provider` is rate limited per IP (`rateLimiting.ssoInitiate`, 30 per 5 minutes by default).

## Handle the result on your frontend

```js
// On https://app.example.com/post-login:
const params = new URLSearchParams(window.location.search);
const fragment = new URLSearchParams(window.location.hash.slice(1));

if (fragment.get('mfa_required') === '1') {
  // The account has MFA. No session yet, no cookies set: ask for a TOTP/recovery code (or a passkey)
  // and POST /auth/mfa/verify { mfaChallengeToken, code } within `expires_in` seconds.
  const mfaChallengeToken = fragment.get('mfa_challenge_token');
  const expiresIn = Number(fragment.get('expires_in'));
  history.replaceState(null, '', window.location.pathname); // drop the token from the address bar
  showMfaPrompt({ mfaChallengeToken, expiresIn });
} else if (params.get('ssoLogin') === 'success') {
  // Cookies are set — fetch('/auth/me', { credentials: 'include' }) to confirm.
} else if (params.get('error') === 'email_not_verified') {
  // Google didn't assert a verified email, so the account can't be created or linked by email.
} else if (params.get('error') === 'email_required') {
  // The provider returned no email — ask the user to try another method, or another account.
} else if (params.get('error') === 'account_inactive') {
  // An existing account with this email is locked/suspended/deleted — SSO never attaches to it.
} else if (params.get('error') === 'provider_error') {
  // The user cancelled at Google, or Google returned an error (`provider_error` has its code).
}
```

The MFA challenge arrives in the URL **fragment** (`#mfa_required=1&mfa_challenge_token=…&
expires_in=…`), which browsers never send to a server or put in a `Referer` header. Completing it
is the same call as after a password login — see
[MFA TOTP Setup & Verify](mfa-totp-setup-and-verify.md).

These redirect outcomes (`ssoLogin=success`, the `mfa_required` fragment, `error=provider_error`,
`error=email_required`, `error=email_not_verified`, `error=account_inactive`) are the callback's
public contract — they don't surface as thrown exceptions your Express error middleware would see.
A missing/expired state or missing binding cookie is a 400 `INVALID_SSO_STATE` from the callback
itself (see [SSO / Social Login](../api/sso-social-login.md)).

If your frontend (on `app.example.com`) then makes cookie-authenticated `POST`/`PUT`/`PATCH`/
`DELETE` calls to the IdP (`/auth/logout`, `/auth/refresh`, …), list its origin in
`cookies.trustedOrigins`, or they're refused with 403 `CSRF_ORIGIN_REJECTED` — see
[Bootstrap & Config](../api/bootstrap-config.md).

## Related

- [SSO / Social Login](../api/sso-social-login.md) — full provider table, state/binding/PKCE
  mechanics, and account-linking rules.
- [Bootstrap & Config](../api/bootstrap-config.md) — `resolveAuthContext` hook shape, `config.sso`.
