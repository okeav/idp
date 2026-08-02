---
title: "Social Login with Google"
package: "@okeav/idp-core"
category: "example"
tags: ["auth", "sso", "oauth2", "google"]
description: "Configure the Google SSO provider and wire the initiate/callback redirect flow, including the redirect-URI allowlist."
---

# Social Login with Google

The same `initiate` → provider → `callback` pattern works for Google, GitHub, Microsoft, Apple,
and LinkedIn — see [SSO / Social Login](../api/sso-social-login.md) for provider-specific details
(Apple and Microsoft need extra config).

## Prerequisites

- A Google OAuth 2.0 Client ID/Secret (Google Cloud Console → APIs & Services → Credentials).
- Google's authorized redirect URI set to this package's own callback endpoint, **not** your
  frontend's post-login page. The exact path depends on both `config.sso.baseCallbackUrl` and
  wherever you mount `buildRouter()` — see the note under Config below. In this example
  (`buildRouter()` mounted at `/auth`, as in the "Start the flow" section), that's
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

  sso: {
    // Required in practice — the package builds an absolute callback URL from
    // this; omitting it produces a relative URL Google will reject.
    //
    // IMPORTANT: this package has zero awareness of where you mount
    // buildRouter() in your Express app — it builds the callback URL as
    // `baseCallbackUrl + '/sso/<provider>/callback'`, nothing more. If you
    // mount the router under a prefix (this example mounts it at `/auth`,
    // matching the Quickstart), that prefix must already be part of
    // baseCallbackUrl, or Google will be sent a redirect_uri your server
    // never actually serves.
    baseCallbackUrl: 'https://idp.example.com/auth',

    // Restrict which redirect_uri values /sso/:provider will accept — set
    // this in production to prevent open-redirect abuse. Unset = no check
    // at all (every redirect_uri is accepted by default).
    allowedRedirectOrigins: ['https://app.example.com'],
  },

  hooks: {
    resolveAuthContext: async (user, ctx) => {
      // ctx = { isNewUser, isNewLink, provider: 'google', extra }
      // `extra` carries any query params your frontend appended to the
      // initiate URL beyond `redirect_uri` — e.g. an `intendedRole` you
      // added below.
      return { claims: { role: 'member' } };
    },
  },
});
```

## Start the flow

```js
function startGoogleLogin() {
  const url = new URL('https://idp.example.com/auth/sso/google');
  url.searchParams.set('redirect_uri', 'https://app.example.com/post-login');
  // Any extra params are captured verbatim and handed back to resolveAuthContext's ctx.extra:
  url.searchParams.set('intendedRole', 'admin');
  window.location.href = url.toString();
}
```

This redirects the browser to `/auth/sso/google`, which itself redirects to Google's consent
screen, which redirects back to `<issuer>/auth/sso/google/callback` (matching `baseCallbackUrl`
above), which (on success) redirects the browser to
`https://app.example.com/post-login?ssoLogin=success` with the session cookies already set.

## Handle the result on your frontend

```js
// On https://app.example.com/post-login:
const params = new URLSearchParams(window.location.search);
if (params.get('ssoLogin') === 'success') {
  // Cookies are set — fetch('/auth/me', { credentials: 'include' }) to confirm.
} else if (params.get('error') === 'email_required') {
  // The Google account had no email in its profile — ask the user to try
  // another method, or another Google account.
} else if (params.get('error') === 'account_inactive') {
  // An existing account with this email is LOCKED/SUSPENDED/DISABLED.
}
```

These three query-string outcomes (`ssoLogin=success`, `error=email_required`,
`error=account_inactive`) are the callback's public contract for the redirect path — they don't
surface as thrown exceptions your Express error middleware would see (see
[SSO / Social Login](../api/sso-social-login.md) for the full list, including the JSON-response
provider-error case that bypasses redirect entirely).

## Related

- [SSO / Social Login](../api/sso-social-login.md) — full provider table, CSRF-state mechanics,
  and account-linking behavior.
- [Bootstrap & Config](../api/bootstrap-config.md) — `resolveAuthContext` hook shape.
