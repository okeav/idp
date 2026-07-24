# @okeav/idp-core — end-to-end test harness

A manual click-through app covering every feature this package ships, for
verifying it works correctly before publishing/distributing it. This is a
test harness, not a polished UI — every page shows the raw request/response
or decoded token so you can visually confirm behavior, not just "it worked."

It consumes `@okeav/idp-core` **only** through its public API and
config, exactly as a real consumer would (`file:../..` dependency, same as
`examples/express-quickstart`). Nothing here reaches into the package's
internals.

## Start it

From the **repo root** (one level up from this folder):

```bash
docker compose up -d       # single-node Mongo replica set + Redis
```

Then, from this folder:

```bash
cd examples/e2e-test-harness
npm install
cp .env.example .env       # optional — only needed for flow 10 (Google SSO)
npm start
```

Open **http://localhost:3100** in a browser. Use `localhost`, not `127.0.0.1`
— flow 8 (WebAuthn) needs the exact origin it's configured for (`rpID:
'localhost'`).

Every restart wipes the harness's in-memory activity log and generates a
fresh signing keypair (invalidating old sessions) — Mongo/Redis data
persists across restarts via the docker-compose volumes, so registered
users/clients/credentials survive.

## What needs your input before you can run all 13 flows

| # | Flow | Needs from you |
|---|---|---|
| 1–9, 11–13 | Everything except SSO | **Nothing** — fully self-contained. |
| 8 | WebAuthn/passkeys | A real browser with a passkey provider available (Windows Hello, Touch ID, a security key, or your OS/browser's built-in passkey offer) — this is a real `navigator.credentials` ceremony, not simulated. Can't be exercised from curl/a script. |
| 10 | SSO | A real Google OAuth 2.0 Client ID + Secret. This package's SSO providers hit hardcoded real provider endpoints (`src/sso/providers.js` in idp-core) — there's no way to stub this without either real credentials or modifying idp-core itself, which this harness deliberately does not do. Exact steps are on the page and in the checklist below. |

Everything else — including MFA (a "compute current code" convenience button
stands in for a real authenticator app), magic link, rate limiting, webhooks,
OAuth2/OIDC, and service mesh — works with zero setup beyond `npm start`.

## Checklist

Tick through in order — later flows assume state from earlier ones (an
active login cookie, MFA enabled, a registered passkey, etc.) as noted.

- [ ] **1. Register → verify email** (`/flows/register`)
  Register a new account → the page shows the dev-mode-captured verification
  code (no real email is sent; the `onVerificationEmailRequested` hook
  writes it here instead) → verify. **Expected:** `201` on register, then
  `{status:'ok'}` on verify. Check the activity panel for `REGISTERED` and
  `EMAIL_VERIFIED`.

- [ ] **2. Login (password)** (`/flows/login`)
  Log in with the account from flow 1. **Expected:** decoded access-token
  claims shown (including the `claims.role` your `resolveAuthContext` hook
  set), plus a raw refresh token. Sets session cookies used by flows 3–9.

- [ ] **3. Refresh token rotation** (`/flows/refresh`)
  Paste the refresh token from flow 2 → refresh → **expected:** a new token
  pair, and the *old* refresh token now rejected with `401
  INVALID_REFRESH_TOKEN` when retried.

- [ ] **4. Logout (single session) / logout all** (`/flows/sessions`)
  List sessions (do flow 2/3 a couple of times first so there's more than
  one) → revoke one by ID → re-list to confirm it's gone → logout (current
  session) → re-list now 401s (correct — you have no valid cookie anymore)
  → log back in via flow 2 → logout all.

- [ ] **5. Forgot / reset password** (`/flows/password-reset`)
  Request a reset for the flow-1 account → dev-mode token shown → reset →
  **expected:** old password now fails at flow 2, new one works, and all
  prior sessions were revoked.

- [ ] **6. MFA (TOTP)** (`/flows/mfa`)
  Requires being logged in (flow 2). Setup → shows the raw `otpauth://` URI
  + secret (no QR renderer — paste the URI anywhere that reads it, or use
  the "compute current code" convenience button) → confirm → login again
  triggers `mfaRequired:true` → complete the challenge. **Expected:** a full
  session issued only after the TOTP step; recovery codes shown once at
  confirm time.

- [ ] **7. Magic link** (`/flows/magic-link`)
  Request a link for a brand-new email → dev-mode token shown, `isNewUser:
  true` → verify → session issued, new `PENDING_VERIFICATION` user promoted
  to `ACTIVE`. Run it again with the **same** email → `isNewUser: false` on
  the second request, same account logs in (no duplicate).

- [ ] **8. WebAuthn / passkeys** (`/flows/webauthn`) — *needs a real browser + passkey provider*
  8a: log in (flow 2), then register a passkey — your browser/OS will
  prompt for a passkey provider. 8b: log out (flow 4), then log in with the
  passkey alone (try both usernameless and email-scoped). 8c: enable TOTP
  MFA (flow 6) *then* register a passkey while still logged in, then trigger
  a normal password login and complete the MFA gate with the passkey
  instead of a code. **Expected:** all three produce a full session; 8b/8c
  fire `resolveAuthContext` exactly like password login (check the panel).

- [ ] **9. OAuth2 / OIDC** (`/flows/oauth2`)
  Requires being logged in (flow 2). Register a test client → approve it →
  authorize (real page navigation — first pass usually lands on a raw
  `consent_required` JSON response; grant consent via the form, then
  authorize again) → lands on `/oauth2-callback` with a `code` → exchange
  for tokens → decode access + ID token → call `/userinfo` → introspect the
  refresh token (`active:true`) → revoke it → introspect again
  (`active:false`).

- [ ] **10. SSO** (`/flows/sso`) — *needs real Google credentials, see table above*
  With credentials configured: click through the real Google consent screen
  → lands on `/sso-callback` → confirms `/auth/me` now reflects the
  Google-authenticated user → reveals the session's JWT via a refresh call.
  Without credentials: page shows exactly what to supply — this is expected
  and not a bug in the harness.

- [ ] **11. Service mesh** (`/flows/service-mesh`)
  Register Service A, then Service B (sequential — the client-side "current
  identity" is one-per-process, matching how a real service would only ever
  be itself) → mint a token as B targeting A → verify it via the remote-JWKS
  path → fetch `/.well-known/services-jwks.json` raw and confirm both
  services' keys are listed.

- [ ] **12. Rate limiting** (`/flows/rate-limit`)
  Fire 10 rapid wrong-password login attempts against one email. **Expected:**
  the first 5 return `401 INVALID_CREDENTIALS`, the rest return `429
  RATE_LIMIT_EXCEEDED` — this harness configures a deliberately low
  threshold (5/5min) specifically so this is visible in a few seconds; see
  idp-core's own README for production defaults (5/15min).

- [ ] **13. Webhooks** (`/flows/webhooks`)
  Pre-configured at boot pointed at this same process's own receiver
  endpoint (webhook targets are deploy-time config in idp-core, not a
  runtime-registrable thing). Trigger register/password-reset → watch
  deliveries appear with an independently-verified signature badge
  (`VALID`/`INVALID`) — also visible as `webhook` entries in the activity
  panel alongside the `hook` entry that triggered them.

## The activity panel

Every page's right-hand sidebar polls `/api/activity` every 1.5s and shows
every `onAuditLog` action and named hook (`onVerificationEmailRequested`,
`onMagicLinkRequested`, etc.) as it fires, plus every received webhook
delivery — so you can confirm a hook actually fired (and with what payload)
without tailing server logs in a separate terminal. It's also printed to the
terminal (`logger: console` in `server.js`) if you want both.

## Design notes (why a few things work the way they do here)

- **Dev-mode "email"**: `onVerificationEmailRequested` /
  `onPasswordResetRequested` / `onMagicLinkRequested` don't send real email —
  they write into an in-memory map this harness reads back on screen. This
  is a harness choice, not something idp-core does; a real app wires these
  hooks to an actual mailer.
- **MFA code entry is manual but has a convenience button**: the code field
  is a plain editable text input (paste a real authenticator's code if you
  have one enrolled against the shown secret); "compute current code" is a
  clearly-labeled shortcut using the same TOTP algorithm, included because
  this is a headless harness, not a phone.
- **OAuth2 authorize/consent runs entirely through `fetch()`**, in one
  continuous script — not a page navigation to `/oauth2/authorize` followed
  by a separate HTML form post. An earlier version of this page used real
  navigation for those two steps, which had a real bug: the "grant consent"
  form's `client_id`/`state` hidden fields were only ever populated by the
  "Authorize" click's JS, so hitting the browser's Back button after landing
  on the `consent_required` JSON page reloaded `/flows/oauth2` fresh and
  wiped them — consent would never actually get recorded, and every
  subsequent "Authorize" click would show `consent_required` again, in a
  loop. Since `fetch()` (unlike `redirect:'manual'`) transparently follows
  redirects and exposes the final `response.url`/`response.redirected` for a
  same-origin destination, the whole round trip — including the redirect an
  already-consented Authorize produces, and the redirect granting consent
  produces — now happens inside one function each, with the
  `consent_required` response's own fields feeding directly into the
  "grant consent" call. Nothing is stashed across a page load.
- **Service mesh registers A then B sequentially**, not concurrently — see
  the note on flow 11 above.
- **Webhooks are boot-time config**, not something this page registers at
  runtime — matches how `config.webhooks` actually works in idp-core.
- **A few requests deliberately omit cookies (`credentials:'omit'`)**: flow 3
  (refresh) and flow 9's "Call /userinfo" button. `authContextMiddleware`
  prefers a cookie over a body-supplied refresh token / `Authorization:
  Bearer` header when both are present — realistic and correct behavior, but
  in a same-origin browser tab you're usually still carrying a login cookie
  from an earlier flow, which would otherwise silently win and mask exactly
  the thing that page is trying to demonstrate. Found this by scripting the
  flows end-to-end while building the harness, not just by inspection —
  worth knowing if you extend this harness further.
