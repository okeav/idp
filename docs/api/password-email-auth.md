---
title: "Password & Email Auth"
package: "@okeav/idp-core"
category: "api-reference"
tags: ["auth", "password", "sessions"]
description: "Registration, login, refresh/logout, password reset/change, self-service profile, and session management handlers."
---

# Password & Email Auth

The primary username/password auth flow, plus self-service account and session management.
Sixteen handlers, all exported from `src/password-auth/controllers.js`.

## Shared session mechanics

Every login method in this package (password, MFA-verify, magic link, WebAuthn, SSO) funnels
through the same internal helpers in `src/password-auth/controllers.js` (module exports used by the
other flows — not part of the public package surface):

- **`issueSession(state, { user, claims, req })`** — mints an access token (`issueAccessToken`,
  carrying `auth_time` = now) and an opaque refresh token, then persists both via
  `sessionRepository.createSessionForLogin(...)` — a single atomic Mongo transaction writing the
  session, an access-token audit record, and `lastLoginAt` together (see
  [Repository Adapters](repository-adapters.md)). The session row is `kind: 'first_party'`,
  records `authTime`, and starts a new **refresh-token family** (`familyId`, `familyCreatedAt` —
  see [Refresh & logout](#refresh--logout)). The session's `jti` is set equal to the paired
  access token's `jti`, so `authContextMiddleware` can resolve a presented access token to its
  session row (`findByJti`, under `session.verifyOnEachRequest`) or to a revocation-cache entry
  keyed by that `jti`. New-device detection runs **before** the session row is written (otherwise
  the device would always already be "known"); if the device is new, `onNewDeviceLogin` fires
  (fire-and-forget, `.catch`-guarded). A user's first-ever login never counts as a new device.
  The row records the user's `sessionEpoch` as read when the sign-in loaded the user — before any
  credential was checked. After the row is written the epoch is read again: if a password reset or
  "log out everywhere" bumped it while the login was in flight, the new row is revoked and the
  login answers 401 `TOKEN_REVOKED`. (A counter, not a timestamp, so it holds whichever app server
  each step ran on.)
- **`setSessionCookies(req, res, state, session)`** — sets the session cookies via
  `cookieOptions()`: `{ httpOnly: true, secure: config.cookies.secure ?? (NODE_ENV !== 'development'), sameSite: config.cookies.sameSite || 'lax', path: '/', domain?: config.cookies.domain }`.
  `secure` defaults to **true** in every environment except `NODE_ENV === 'development'` with no
  explicit override. Three cookies (names since 0.4.0, against cookie tossing from a sibling
  subdomain):

  | Cookie | Secure, no `cookies.domain` | Secure, with `cookies.domain` | Without Secure | Path |
  |---|---|---|---|---|
  | access token | `__Host-access_token` | `__Secure-access_token` | `access_token` | `/` |
  | refresh token | `__Secure-refresh_token` | `__Secure-refresh_token` | `refresh_token` | `<mount path>/session` |
  | refresh binding | `__Host-refresh_binding` | `__Secure-refresh_binding` | `refresh_binding` | `/` |

  The **refresh cookie** is scoped to the session endpoints — `<mount path>/session` (the router's
  `req.baseUrl` as the request spelled it, e.g. `/auth/session`; set `cookies.sessionPath` to pin
  it), where `/session/refresh`, `/session/logout`,
  `/session/logout/all` and `/session/end` live — so the long-lived token is sent nowhere else. A
  path-scoped cookie can't carry `__Host-` (which needs `Path=/`, and is what a sibling subdomain
  can't plant), so it comes with the host-only **binding cookie**, holding a keyed hash of the
  token (`HASH_PURPOSES.REFRESH_COOKIE_BINDING`). The IdP uses the refresh-cookie value whose
  keyed hash a binding cookie holds; values without one — planted, since the planter can't set the
  host-only binding — are ignored, so they can neither be used nor block refresh, logout or
  end-session. Every refresh-cookie value is considered (planted ones can't crowd out the real one); in host-only mode (no
  `cookies.domain`) a request carrying more than one binding cookie gets no refresh cookie at all —
  a browser holds exactly one, so several can only be forged. Only two *different* tokens that each
  come with a matching binding are refused (400 `COOKIE_CONFLICT`) — possible only with
  `cookies.domain`, where the binding is a domain cookie too. The binding alone is useless; it isn't the token. The access-token cookie sent twice is
  refused with 400 `COOKIE_CONFLICT`. With `cookies.domain` (cookies shared across subdomains by
  choice) all three carry `Domain`.
- **`refreshTokenInBody`** — whether the refresh token is also returned in login/refresh JSON
  bodies (`config.cookies.refreshTokenInBody`, env `IDP_COOKIE_REFRESH_TOKEN_IN_BODY`). The default
  `'auto'` includes it only for non-browser clients: a request carrying `Origin` or
  `Sec-Fetch-Site` gets it only in its httpOnly cookie, out of reach of page script. `true` always
  includes it (a browser app that keeps the refresh token itself — set this if your browser code
  reads `refreshToken` from the body, as the 0.3.x default allowed); `false` never does. See
  [Bootstrap & Configuration](bootstrap-config.md#cookiesrefreshtokeninbody).
- **`resolveClaims(state, user, ctx)`** — calls `hooks.resolveAuthContext(user, ctx)`, returns
  `result?.claims ?? {}`.
- **`assertUsableStatus(user)`** — throws based on `user.status`: `LOCKED` (an **administrative**
  lock — see [Lockout](#failed-password-lockout)) → `ACCOUNT_LOCKED` 423;
  `SUSPENDED`/`DISABLED` → `ACCOUNT_SUSPENDED` 403; `PENDING_VERIFICATION`/`INVITED` →
  `PENDING_VERIFICATION` 403; `DELETED` → `INVALID_CREDENTIALS` 401 (**deliberately
  indistinguishable from a wrong password** — a soft-deleted account's login attempts look
  identical to bad credentials); any other value → `USER_NOT_ACTIVE` 403; `ACTIVE` returns
  silently. A pre-0.4.0 row with status `LOCKED` *and* a `lockUntil` counts as `ACTIVE` here (it
  was a failed-password lock). The password lockout itself (`lockUntil`) is not checked here — it
  only affects password login. (Password login never reaches the `PENDING_VERIFICATION` branch —
  see [Login](#login).)

## Hooks on enumeration-sensitive endpoints

Register, resend-verification and forgot-password (and magic-link request) must answer the same
whether or not an account exists (register and resend-verification hand out a
[verification ticket](#verification-tickets) on every path for the same reason). Their email hooks — `onVerificationEmailRequested`,
`onPasswordResetRequested` — and their audit events are therefore **started but not awaited**: if
the response waited for an email to be sent, it would come back measurably later for real
accounts. The hook's first synchronous step still runs before the response. In a serverless
runtime, make those hooks hand off quickly (enqueue rather than send inline). Every other hook is
awaited for at most `config.hookTimeoutMs` (default 10 s); a hook that runs longer keeps running,
but the request carries on.

## Registration

**`POST /register`** — body `{ email, password, firstName?, lastName?, metadata? }`
(`registerSchema`, `.strict()`).

Password policy (enforced by zod, applies everywhere a *new* password is set — register, reset,
change — not on login): min 8 / max 128 chars **and at most 72 bytes of UTF-8** (bcrypt ignores
everything past 72 bytes, so longer passwords are refused rather than silently truncated — that's
72 ASCII characters, fewer with multi-byte characters), must contain uppercase, lowercase, a
number, and a special character (`PASSWORD_POLICY_DEFAULTS`).

`metadata` is **ignored** unless `config.registration.acceptMetadata: true`; then it's persisted
verbatim on the user record (never interpreted) and handed to `resolveAuthContext`. It's written
by whoever registers, so never keep a role, tenant or plan there — see
[Storing App-Specific User Data](../examples/consumer-managed-app-data.md).

Rate limited per IP (`register:ip:<ip>` against `config.rateLimiting.register`, 10/hour default)
and per address (`verification-email:<email hash>` against
`config.rateLimiting.verificationEmailByEmail`, 3/hour default) — both fail-closed (a limiter
backend error → 503 `RATE_LIMITER_UNAVAILABLE`), and both counted on every request, before the
address is looked up.

**Always responds `201 { status: 'ok', verificationTicket }`** and sets the ticket cookie —
identical whether the email was new, pending, or already active (enumeration-safe; see
[Verification tickets](#verification-tickets)). The password is bcrypt-hashed on every path, so response timing
doesn't leak whether an account exists either.

- **New address**: creates the user in `PENDING_VERIFICATION` status, mints **both** a 32-byte
  opaque verification token *and* a separate 6-digit numeric code (`crypto.randomInt(100000,
  1000000)`) — stored together (both as HMACs) so your email template can offer either a link or
  a code (see [the code cap](#codes-per-address) below: `verificationCode` can be `null`) — and fires `auditLog('REGISTERED', ...)` + `onVerificationEmailRequested({ email,
  firstName, lastName, verificationToken, verificationCode })`.
- **Address still `PENDING_VERIFICATION`**: nobody has proven they own it yet. Every verification
  code is **bound to the password of the registration that sent it** (its token row stores that
  registration's `passwordHash`), so a repeat registration does **not** delete earlier codes or
  overwrite the profile: it mints a fresh token+code pair bound to its own password, marks the
  account `registrationContested: true` (`auditLog('REGISTRATION_REPEATED')` +
  `onVerificationEmailRequested`). From then on, verifying needs the password too (see below), so
  the inbox owner activates *their own* registration's password — whichever order the attacker
  and the victim registered in. The write is conditional on the account **still** being pending
  (`userRepository.updateByIdIfStatus`): if it was activated meanwhile (verify-email, magic link,
  SSO, reset), the repeat registration changes nothing and sends nothing.
- **Any other existing account**: untouched; no email is sent.

**`POST /register/verify-email`** — body `{ email, token? | code?, password?, ticket? }` (`.refine`s
that at least one of `token`/`code` is present; `password` is optional, 1–1024 characters;
`ticket`, at most 256 characters, is the [verification ticket](#verification-tickets) — when
omitted, the ticket cookie is used). If `token` is
provided it's preferred over `code`. Rate limited per IP (`email-verification:ip:<ip>` against
`config.rateLimiting.emailVerification`, 20/15min default, fail-closed).

- **Contested addresses** (registered more than once before verification): a valid code/token
  also needs the `password` of the registration it belongs to. **Missing** → 400
  `REGISTRATION_PASSWORD_REQUIRED`; **wrong** → 400 `INVALID_OR_EXPIRED_TOKEN`, the same answer as
  a wrong code. Either way the code **stays usable** (for a code, the attempt still counts toward
  the limits below). Show a password field and resend with `{ email, code, password }`.
  An uncontested address verifies with the code alone.

- **Read, check, then consume.** The handler finds the live row without consuming it
  (`verificationTokenRepository.findActive`), checks the contested password, and only then
  consumes it (`consumeByHash` / `consumeByCode`) — a refused attempt never takes a code out of
  circulation, and of two concurrent requests with the same code only one succeeds.
- **Enumeration-safe**: an unknown address, an already-verified one, and a wrong code all answer
  the same 400 `INVALID_OR_EXPIRED_TOKEN`. (So a second click on an already-used verification link
  gets 400, not `ok`.)
- **Attempt budgets on the 6-digit code** (`config.security.verificationCodeLockout`, default 5
  wrong attempts per 24 h window, then locked for 24 h; both window and lock are raised to at least
  `ttls.emailVerification` wherever they are used, so a budget lasts as long as the code). An
  attempt carrying a live [verification ticket](#verification-tickets) for this address spends
  **that ticket's own budget** (`email-verification:ticket:<ticket hash>`). Any other attempt spends
  the **per-address** budget (`email-verification:<email hash>`). Both work the same for unknown,
  already-verified and pending addresses — so neither says whether a pending registration exists.
  A stranger can use up the per-address budget, but not the registrant's ticket. Only the
  **code** path is budgeted: the 32-byte link `token` can't be guessed, so it has no budget and
  keeps working whatever happens to the code. Attempts are counted **before** the code is checked,
  so a concurrent burst gets no more guesses than the budget. The attempt that uses up a budget
  answers 429 `VERIFICATION_LOCKED` (and, for a pending account, fires
  `auditLog('EMAIL_VERIFICATION_LOCKED', { userId, withTicket })`), as does every further attempt
  on that budget while it is locked. A spent budget locks only its own attempts — **the codes are no
  longer cleared**, so the registrant's ticket and the link keep working. The counters live in the
  `attemptCounterRepository` when your storage adapter has one (shared by every instance),
  otherwise in-process.
- **Year-long cap per address** (`verificationCodeLockout.maxTotalFailedAttempts`, default 20):
  every code attempt that passes its ticket or address budget also counts toward
  `email-verification-total:<email hash>`, whatever ticket it carries, over a year-long window. Once
  20 wrong codes have been checked for an address, every further code attempt answers 429
  `VERIFICATION_LOCKED` and only the link works. So an address's codes are guessed at most 20
  times a year, however often someone registers, resends or collects tickets — each guess tried
  against the few codes live at the time (at most 3 issued per code lifetime, see below). A
  correct code resets the counters it passed through (the link path doesn't touch them).
- On success: promotes to `ACTIVE` — **only while the account is still pending**
  (`updateByIdIfStatus`; if another path settled it meanwhile, 400 `INVALID_OR_EXPIRED_TOKEN`) —
  **activates the password bound to the code** (rows from before 0.4.0 carry none and keep the
  account's), clears `registrationContested`, deletes **all** outstanding `email_verification`
  tokens for the user, retires the ticket the request carried and clears the ticket cookie, fires `auditLog('EMAIL_VERIFIED')`, and answers `200 { status: 'ok', userId,
  email }`.

Codes issued before 0.4.0 were stored in plain text; they keep working until they expire (only a
6-digit value is tried that way — the stored HMAC of a newer code is never accepted as a code).

Errors: `INVALID_OR_EXPIRED_TOKEN` (400), `REGISTRATION_PASSWORD_REQUIRED` (400),
`VERIFICATION_LOCKED` (429), `RATE_LIMIT_EXCEEDED` (429).

**`POST /register/resend-verification`** — body `{ email }`. Always `200 { status: 'ok',
verificationTicket }` plus the ticket cookie — unknown, already-verified and pending addresses get
the same answer, **at the same speed**: the response is sent first, and the lookup, writes and hook
run after it (the ticket is issued before the response, the same way for every address). Rate limited (before the
response) by the same `register` (per IP) and `verificationEmailByEmail` (per address) limits as
`/register`. For a pending account it deletes prior tokens before minting a new token+code pair
(old links/codes become invalid) and fires `onVerificationEmailRequested` — except on a contested
account, where earlier codes are kept and the new one is bound to the most recent registration's
password.

<a id="codes-per-address"></a>**At most 3 codes per address per code lifetime.** Each
verification email (registration, repeat registration, resend) counts toward
`verification-codes:<email hash>` (a fixed window of `ttls.emailVerification`, so around a window's
end a few more codes can be live at once — still a small, fixed number). From the fourth one on, the
email carries **only the link**: `onVerificationEmailRequested` receives `verificationCode: null`
(the token row has no code). **Your email template must handle that** — always include the link
(`verificationToken`), and the code only when it isn't `null`:

```js
onVerificationEmailRequested: async ({ email, verificationToken, verificationCode }) => {
  const link = `https://app.example.com/verify-email?email=${encodeURIComponent(email)}&token=${encodeURIComponent(verificationToken)}`;
  await sendEmail(email, verificationCode
    ? `Your code is ${verificationCode} — or open ${link}`
    : `Open ${link} to verify your address`);
},
```

### Verification tickets

The 6-digit code is guessable, so attempts at it are budgeted — and a budget anyone can spend is
one a stranger can use up for the address's owner. So whoever registers, or asks for a resend, gets
a **verification ticket**: a 32-byte random value, returned as `verificationTicket` in the JSON
body and set as a host-only httpOnly cookie, `__Host-verification_ticket` (`Secure`,
`SameSite=Lax`, `Path=/`, max-age `ttls.emailVerification`; plain `verification_ticket` without
Secure). `/register/verify-email` reads the `ticket` body field, else the cookie; code attempts that
carry a live ticket for the address spend the ticket's own budget (see above).

- **Per address, and for every caller.** A ticket is issued for the *address* (keyed by the
  email's blind index) and stored in the attempt-counter store
  (`verification-ticket:<email hash>:<ticket hash>`, living `ttls.emailVerification`) whether or
  not the address has an account. What a ticket does never depends on the account, so neither the
  answer nor the ticket says whether one exists.
- **At most 5 stored tickets per address per code lifetime** (counted as
  `verification-tickets:<email hash>`); later callers are still handed a ticket, but it isn't
  stored, so it only ever gets the per-address budget. This bounds the guesses anyone can collect.
- **A caller that already holds a live ticket cookie for the address keeps it** on register and
  resend (the same value comes back in `verificationTicket`), so resending doesn't use up the quota.
- A browser that calls the IdP with credentials sends the cookie back by itself. A client that
  doesn't — a native app, a `fetch` without `credentials: 'include'`, a cross-site frontend (the
  cookie is `SameSite=Lax`) — sends the `verificationTicket` it received as `ticket`. Without a ticket, attempts fall back to the
  per-address budget, and the emailed link always works.
- Tickets are stored only as keyed hashes (`HASH_PURPOSES.EMAIL_VERIFICATION_TICKET`). They live in
  the `attemptCounterRepository` — without one, in the in-process fallback, so a ticket is then
  only recognised by the instance that issued it. A ticket cookie sent twice is refused with 400
  `COOKIE_CONFLICT`.

## Login

**`POST /login`** — body `{ email, password, login_challenge? }` (`login_challenge`: from an
`/oauth2/authorize` `login_required` answer — the new session, or the MFA challenge, is bound to
it; see [Login challenges](oauth2-authorization-server.md#login-challenges); password here is just `z.string().min(1).max(1024)`
— the strong-password policy is **not** re-applied on login, correctly, since it must accept legacy
passwords). Rate limited on two independent keys: `login:ip:<ip>` against
`config.rateLimiting.login` (10/15min default) and `login:email:<email hash>` against
`config.rateLimiting.loginByEmail` (5/15min default). Both fail closed: a rate-limiter backend
error → 503 `RATE_LIMITER_UNAVAILABLE`. (Per-address keys use the email's keyed hash, so the
limiter backend and logs never hold the address; IPv6 clients are keyed by their /64.)

**Legacy locks**: a lock recorded on the user row before 0.4.0 (`lockUntil`) is still honoured
until it runs out; once it has passed, the handler clears `failedLoginAttempts`/`lockUntil` (and a
pre-0.4.0 `LOCKED` status) *before* checking the password on this same request. Since 0.4.0 the
lockout itself lives in the attempt counter (see [Lockout](#failed-password-lockout)).

**Timing-safe non-enumeration**: a nonexistent email still runs `compareDummyPassword` so the
response takes comparable time to a wrong-password attempt against a real account. The dummy hash
is generated at startup with `config.security.bcryptRounds`, so its cost matches real hashes. An
account with no password (SSO- or magic-link-only) does the same dummy work and fails like a wrong
password — it doesn't 500.

**Pending accounts**: a `PENDING_VERIFICATION` account answers 401 `INVALID_CREDENTIALS`, right
password or not (a distinct "pending" answer would tell whoever registered the address whether
someone else has registered it since).

**While password login is locked, every password gets 401 `INVALID_CREDENTIALS`** — the right one
included. If the lock answered differently for the right password, it would become a password
oracle. A locked attempt still spends a bcrypt compare, so its timing doesn't stand out either. The
lock was announced through `onSuspiciousActivityDetected`; a password reset lifts it.

**In-flight logins and sign-out.** The time the credential check began is recorded; if a password
reset or "log out everywhere" lands while the login is running, the new session is revoked right
after it's written and the login answers 401 `TOKEN_REVOKED` (see `issueSession` above).

**MFA branch**: if `user.mfaEnabled`, responds `200 { mfaRequired: true, mfaChallengeToken,
expiresIn: config.ttls.mfaChallenge }` (note: `expiresIn` is a **duration in seconds**, unlike
every other endpoint here which returns absolute `...ExpiresAt` timestamps) — no session issued
yet; complete via [`verifyMfaChallengeHandler`](mfa.md) or the WebAuthn-MFA flow. The challenge
token completes one login only.

**Success (no MFA)**: sets cookies + `200 { accessToken, accessTokenExpiresAt, refreshToken,
refreshTokenExpiresAt, userId }` (`refreshToken` only as `cookies.refreshTokenInBody` allows — by
default, only for non-browser clients).

**Errors**: `INVALID_CREDENTIALS` (401 — unknown user, wrong password, password login locked, a
pending account, or `DELETED` status), `TOKEN_REVOKED` (401 — signed out everywhere while the login
was in flight), `CSRF_ORIGIN_REJECTED` (403 — see below), `INTERNAL_ERROR` (500 — the attempt
counter's backend failed; the login fails closed), plus whatever `assertUsableStatus` throws for
suspended or administratively locked accounts.

**Login CSRF.** `/login` sets session cookies, so every browser request to it is subject to the
[CSRF origin check](middleware.md#csrf-origin-check) — cookie or not: an `Origin` that is neither
the issuer's nor in `cookies.trustedOrigins` gets 403 `CSRF_ORIGIN_REJECTED` (otherwise a form on a
sibling origin could sign the victim into the attacker's account). The same applies to `/session/refresh`,
`/session/logout`, `/mfa/verify`, `/magic-link/verify`, `/webauthn/authentication/verify` and
`/webauthn/mfa/verify`. Non-browser clients (no `Origin`/`Sec-Fetch-Site`) are unaffected.

### Failed-password lockout

Password login on an `ACTIVE` account **that has a password** runs inside a per-account attempt
budget (an account without a password, or a pending one, has nothing to guess and is never locked
or alerted on — its compare still runs, for timing), keyed `password-login:<userId>` in the
`attemptCounterRepository` (shared by every instance when your storage adapter has one, otherwise
in-process): `config.security.maxFailedLoginAttempts` (default 5) wrong passwords per
`config.security.accountLockDurationMs` window (default 30 min), then password login is locked for
`accountLockDurationMs`. The attempt is counted **before** bcrypt runs, so a concurrent burst gets
no more guesses than the budget (counting after a failure let every request of a burst be
checked). The wrong password that uses up the budget fires `auditLog('ACCOUNT_LOCKED', ...)` +
`onSuspiciousActivityDetected`. A correct password resets the count; other sign-in methods do
**not** (signing in by magic link mustn't hand a guesser a fresh budget); a completed password
reset does. A counter backend error fails closed (500). Wrong MFA codes don't count here — MFA has
its own lockout (see [MFA](mfa.md)). The user row's `failedLoginAttempts` / `lockUntil` are no
longer written by the lockout (only read, for rows locked before 0.4.0).

The lockout locks **password login only** — the account's status stays `ACTIVE`. Refresh and
existing sessions, magic link, passkeys, SSO, MFA and the OAuth2 grants keep working. Rows locked
before 0.4.0 (status `LOCKED` with a `lockUntil`) are treated the same until `lockUntil` passes and
are normalised to `ACTIVE` on the next sign-in. A `LOCKED` status **without** `lockUntil` is an
**administrative lock** set by your app:
it blocks every method (`ACCOUNT_LOCKED` 423 on magic link / passkey / password login with the
right password, `USER_NOT_ACTIVE` 403 on refresh and MFA, `INVALID_GRANT` at `/oauth2/token`), and
a password reset does not lift it.

## Refresh & logout

> **Revocation and access tokens.** With `config.session.verifyOnEachRequest` on (the default
> since 0.3.0), every revocation below — refresh rotation, reuse detection, logout, logout-all,
> password reset/change, `DELETE /me`, `DELETE /me/sessions[/:id]` — kills the affected access
> tokens on every instance at once, because `authContextMiddleware` checks the session row on each
> request. The revocation-cache notes below (which operations write a `jti` entry, and that bulk
> ones don't) only decide behaviour when it's set to `false` — then tokens from bulk-revoked
> sessions stay valid until natural expiry. See [Middleware](middleware.md).

**Session kinds.** Session rows are `kind: 'first_party'` (a login on this IdP) or `kind:
'oauth2'` (an OAuth2 client's grant). `/session/refresh` accepts only `first_party` rows; an OAuth2 client's
refresh token presented here is refused with `INVALID_REFRESH_TOKEN` and **revoked** (reason
`misused`, not a rotation — it leaked). Rows written before 0.4.0 have no `kind` and are
classified by their stored claims (`{ clientId, scopes[] }` = OAuth2).

**Refresh-token families.** A login starts a family (`familyId`, `familyCreatedAt`); every
rotation adds a row to it. Two rules hang off that:

- **Absolute lifetime** — a family ends `config.session.absoluteLifetimeSeconds` (default 90 days)
  after its login, however actively it's refreshed: no refresh token's expiry is set past that, and
  a refresh after it answers `INVALID_REFRESH_TOKEN` ("maximum lifetime"). The usual sliding
  `ttls.refreshToken` (30 days) applies inside it.
- **Reuse detection** — presenting a refresh token that was already *rotated* means someone holds
  a copy, so the whole family is revoked (both the thief and the legitimate client must log in
  again) and `auditLog('REFRESH_TOKEN_REUSE_DETECTED')` fires. Within
  `config.session.refreshReuseGraceSeconds` (default 10 s — two tabs refreshing at once) a replay
  is only refused. The window is measured by the database alone: the rotation's `revokedAt` is
  written with the database clock and `sessionRepository.rotatedWithin(hash, seconds)` compares
  against that same clock, so app servers whose clocks differ agree on it. Needs the storage
  methods `findByRefreshTokenHash` and `revokeFamily`; an
  adapter without `revokeFamily` just refuses the replay. `revokeFamily` also tombstones every row
  of the family (`familyRevokedAt`), and a refresh checks `sessionRepository.isFamilyRevoked` after
  inserting its successor — so a legitimate refresh racing the replay can't leave a live successor
  behind (it's revoked and the refresh answers 401 `TOKEN_REVOKED`).

**`POST /session/refresh`** — reads the refresh token from `req.body.refreshToken` or the refresh-token
cookie (`__Secure-refresh_token`, the value matching its binding cookie — see
[cookie names](#shared-session-mechanics)); **a token in the
body wins** (it's explicit; the cookie is whatever the browser holds, which a sibling subdomain may
have planted). The body is validated by `refreshSchema` (`{ refreshToken? }`,
a string of at most 512 characters). Rate limited: `refresh:ip:<ip>` against
`config.rateLimiting.refreshToken` (30/min default — fail-open, it's load-shedding). Every browser
request — whether the token came from the cookie or the body — is subject to the
[CSRF origin check](middleware.md#csrf-origin-check) (`cookies.trustedOrigins`), since `/session/refresh`
sets session cookies; the check runs first, before any cookie is read.

**Checks first, then rotates.** Every check that can refuse or fail — the row is live, it is a
`first_party` row, the user is active, the family's absolute lifetime, `resolveAuthContext` (when
claims are re-resolved) —
runs **before** the token is consumed, so a refused or failed refresh does not burn it (the
client's retry isn't mistaken for reuse).

**Rotates on every use**: then atomically revokes the presented refresh token
(`sessionRepository.revokeByRefreshTokenHash(hash, { reason: 'rotated' })`) and issues a brand-new
access+refresh pair in the same family (a plain `createSession`, not the transactional
`createSessionForLogin` — this isn't a new login). The new access token keeps the **original
login's `auth_time`** — a refresh never counts as a recent login for
[`requireRecentAuth`](middleware.md#requirerecentauthopts). Also writes a revocation-cache entry for
the **old** access token's `jti` (`config.ttls.revocationCache`, default 3600s) so it stops working
immediately rather than at natural JWT expiry (it's also refused through its now-revoked session
row).

**Claims are re-resolved on every refresh** by default (`config.session.reresolveClaimsOnRefresh`,
default **`true`** since 0.4.0): `resolveAuthContext` runs again with `{ isNewUser: false, method:
'refresh' }`, so a role change or suspension in your app takes effect at the next access-token
rotation instead of the next full login. Keep the hook fast. Set it to `false` to carry the
login-time claims forward unchanged — they then stay frozen for the whole family (up to
`absoluteLifetimeSeconds`).

**Racing "log out everywhere".** Logout-all, revoke-all-sessions, password reset/change and
account deletion increment the user's `sessionEpoch` (`userRepository.bumpSessionEpoch`) *before*
revoking the rows. Every session row records the epoch its chain was authenticated in, and its
successor inherits it; a refresh re-reads the user's epoch after writing the successor and, if it
has moved past the chain's, revokes the new row and answers 401 `TOKEN_REVOKED`. MFA enrolment
bumps the epoch with the enrolling session's family exempt (`sessionsRevokedExceptFamily`), so a
refresh of another session already in flight is caught too. Counters rather than timestamps: the
outcome doesn't depend on the app servers' clocks agreeing.

Errors: `REFRESH_TOKEN_REQUIRED` (400 — no token in the body and no refresh cookie with a matching
binding), `VALIDATION_ERROR` (400, e.g. a non-string token), `COOKIE_CONFLICT` (400 — two different
refresh tokens each with a matching binding; only possible with `cookies.domain`),
`INVALID_REFRESH_TOKEN` (401 — no matching active session, a reused/rotated token, an OAuth2 row,
or the family's absolute lifetime passed), `TOKEN_REVOKED` (401), `USER_NOT_ACTIVE` (403),
`CSRF_ORIGIN_REJECTED` (403).

**`POST /session/logout`** — body `{ refreshToken? }` (`logoutSchema`; the body itself may be omitted).
Reads the refresh token from `req.body.refreshToken` or, when the body omits it, the httpOnly
refresh-token cookie (body wins, as at `/session/refresh`). **Every** browser request is subject to the
[CSRF origin check](middleware.md#csrf-origin-check), body token or not — logout clears the
session cookies, so a cross-site form could otherwise sign the victim out. Revokes the session
(`onlyIfActive: false` — explicitly allows revoking an already-inactive row) and, if found, writes
a revocation-cache entry for its `jti`. Clears the session cookies (access, refresh and binding,
plus the `Path=/` refresh cookie of earlier 0.4.0 builds) with the same attributes they were set
with (path, and `config.cookies.domain`) — **also when it answers `REFRESH_TOKEN_REQUIRED`** (400,
no token in the body and no refresh cookie with a matching binding, e.g. only a planted one), so the
browser ends up signed out either way. Other errors: `COOKIE_CONFLICT` (400, two bound tokens —
`cookies.domain` only; the cookies are cleared then too), `CSRF_ORIGIN_REJECTED` (403).

**`POST /session/logout/all`** (auth required) — bumps the user's `sessionEpoch`, then revokes every session
for the caller (`revokeAllForUser`) but, unlike `revokeAllSessionsHandler` below, does **not**
return `revokedCount` and does **not** write per-session revocation-cache entries — with
`session.verifyOnEachRequest: false`, already-issued access tokens for those sessions stay valid
until natural expiry. Fires `auditLog('LOGOUT_ALL', ...)`.

## Password management

**`POST /password/forgot`** — body `{ email }`. Always `200 { status: 'ok' }` (enumeration-safe —
silent no-op if the email is unknown or the account is deleted, no audit log fired in that case
either). The response is sent **before** the address is looked up — the lookup, the writes and the
hook run after it — so it takes the same time for every address. Rate limited (before the
response) per IP (`password-reset:ip:<ip>` against `config.rateLimiting.passwordReset`, 3/hour
default) **and** per address (`password-reset:email:<email hash>` against
`config.rateLimiting.passwordResetByEmail`, 3/hour default), both fail-closed (503
`RATE_LIMITER_UNAVAILABLE` on a backend error). Only the newest link works: a new request replaces
the account's reset token atomically (`verificationTokenRepository.replaceForUser`, backed by a
partial unique index — one live reset link per user even under concurrent requests). Reset token: 32-byte opaque, hash-only (no numeric-code
counterpart, unlike email verification). Fires `onPasswordResetRequested({ email, resetToken,
firstName?, lastName? })` (detached — see above) only if the user exists.

**`POST /password/reset`** — body `{ email, token, newPassword }` (full password policy).
`INVALID_OR_EXPIRED_TOKEN` (400) for both "no such user" and "token invalid/expired/wrong owner" —
deliberately non-distinguishing. On success: rehashes, sets `passwordChangedAt` (which also voids
any outstanding MFA challenge token), **lifts a password lockout** (the `password-login:<userId>`
counter is reset and a legacy `failedLoginAttempts`/`lockUntil` cleared; a pre-0.4.0 `LOCKED` +
`lockUntil` row back to `ACTIVE` — an administrative lock stays), **revokes all sessions** for the
user (forces re-login everywhere), and deletes every other outstanding reset token. On a
**never-verified** (`PENDING_VERIFICATION`) account the reset also **activates** it — it proved the
inbox, like a magic link — conditionally on it still being pending (`updateByIdIfStatus`): status
`ACTIVE`, `registrationContested: false`, MFA state cleared (`mfaEnabled: false`, secrets and
recovery codes removed — set before the address was proven), and every outstanding
`email_verification` row deleted
(a pre-registration's code could otherwise later activate *its* password over the one just set). It does **not** fire `onPasswordChanged` (that hook is exclusive to
`/password/change` below) and does not write revocation-cache entries for already-issued access
tokens — they die with their session rows under `session.verifyOnEachRequest` (default), and
otherwise remain valid until natural expiry.

**`POST /password/change`** (auth required) — body `{ currentPassword, newPassword }`.
`CURRENT_PASSWORD_INCORRECT` (400) if the bcrypt compare fails (always the case for an account with
no password). Wrong current passwords count against a per-account budget
(`config.security.passwordChangeLockout`, default 5 per 3600 s, locked for 3600 s — counted in the
`attemptCounterRepository` like the verification-code budget): the attempt that exhausts it, and
every attempt while locked (right password or not), answers 429 `PASSWORD_CHANGE_LOCKED`
(`auditLog('PASSWORD_CHANGE_LOCKED')` fires once, when the lock starts). Without it, a stolen access token would be an
unlimited password oracle. Same rehash + `passwordChangedAt` + revoke-all-sessions pattern as reset, **plus**
fires `onPasswordChanged({ userId, email, firstName, lastName, locale, when, deviceInfo, ipAddress })`.

## Self-service identity ("me")

All require `authContextMiddleware()` (first-party tokens only) → `UNAUTHENTICATED` (401) if
missing.

- **`GET /me`** → `{ userId, email, emailVerified, isActive, status, mfaEnabled, profile,
  createdAt, updatedAt }`. `emailVerified` is **derived**, not a stored field:
  `status !== 'PENDING_VERIFICATION'` — so `LOCKED`/`SUSPENDED`/`DISABLED`/`DELETED` all read
  `emailVerified: true` too; only the pending-verification state reads `false`. `status` is the
  **effective** status — a pre-0.4.0 automatic lock (`LOCKED` with a `lockUntil`) reads `ACTIVE` —
  and `isActive` is `status === 'ACTIVE'` on that effective status.
- **`PATCH /me`** — body may include any of `firstName, lastName, displayName, avatarUrl, locale,
  zoneinfo` (`updateProfileSchema`, all optional). `avatarUrl` must be an `https` URL (it's
  released as the ID token's `picture`); `locale` must be a BCP 47 tag and `zoneinfo` an IANA
  zone name. Builds a sparse dotted-path patch — only keys explicitly present (`!== undefined`)
  are updated; omitted keys are left untouched, not nulled. → `{ userId, profile, updatedAt }`.
- **`DELETE /me`** — also requires a **recent login**
  ([`requireRecentAuth()`](middleware.md#requirerecentauthopts), default within 15 minutes; else 401
  `REAUTHENTICATION_REQUIRED`). **Soft delete**: sets `status: 'DELETED'` (record is not removed)
  and revokes all sessions. Combined with `assertUsableStatus`'s `DELETED → INVALID_CREDENTIALS`
  mapping, a deleted user's future login attempts are indistinguishable from wrong credentials.
- **`GET /me/sessions`** → array of `{ id, ipAddress, deviceInfo, createdAt, expiresAt }` — does
  **not** expose `deviceFingerprint`, `jti`, `kid`, `claims`, or `tokenHash` even though those
  fields exist on the stored record.
- **`DELETE /me/sessions/:id`** → `REFRESH_TOKEN_NOT_FOUND` (404) if the session doesn't exist,
  isn't owned by the caller, or the id is malformed (all collapse to the same error). On success,
  proactively revokes the session's `jti` in the cache (kills its access token immediately) —
  **unlike** the bulk variant below.
- **`DELETE /me/sessions`** → revokes every session and returns `{ status: 'ok', revokedCount }`.
  Does **not** write per-session revocation-cache entries (same caveat as `/session/logout/all`) —
  functionally overlaps with `/session/logout/all` but reports `revokedCount` and fires a different audit
  event (`SESSIONS_REVOKED_ALL` vs `LOGOUT_ALL`).

## Related

- [MFA](mfa.md) — completes the `mfaRequired` challenge this flow issues.
- [Magic Link](magic-link.md), [WebAuthn](webauthn.md), [SSO / Social Login](sso-social-login.md) —
  alternative login methods sharing `issueSession`/`resolveClaims`/`assertUsableStatus`.
- [Middleware](middleware.md) — `authContextMiddleware`, `requireRecentAuth`, the CSRF origin check.
- [Rate Limiter Interface](rate-limiter-interface.md), [Cache Interface](cache-interface.md)
- [Register, Login, Refresh example](../examples/register-login-refresh-logout.md)
