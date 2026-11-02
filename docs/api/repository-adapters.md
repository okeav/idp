---
title: "Repository Adapters (Storage)"
package: "@okeav/idp-core"
category: "api-reference"
tags: ["mongodb", "storage-adapter", "repository"]
description: "The eight repository interfaces (plus the optional attempt counter), the built-in MongoDB adapter, the storage.factory pluggability contract, and the transaction requirement."
---

# Repository Adapters (Storage)

MongoDB is the only concrete storage adapter shipped in this version, behind **eight repository
interfaces** documented as JSDoc typedefs in `src/storage/interfaces.js` (the canonical contract —
`types/index.d.ts` loosely types `StorageContract` fields as `unknown` and points here for the
full per-repository shapes). A separate adapter (Postgres, DynamoDB, ...) implements the same eight
interfaces; nothing above the storage layer needs to change.

Several newer pieces are **optional**: an adapter without them still boots and works, but with a
weaker fallback — some logged at startup, some when first needed. See
[Optional methods and their fallbacks](#optional-methods-and-their-fallbacks).

## `StorageContract`

```ts
interface StorageContract {
  connection?: unknown;      // adapter-specific raw handle (e.g. Mongoose connection) — optional
  close(): Promise<void>;    // required by every adapter, for teardown
  userRepository: UserRepository;
  sessionRepository: SessionRepository;
  authorizationCodeRepository: AuthorizationCodeRepository;
  consentRepository: ConsentRepository;
  oauthClientRepository: OAuthClientRepository;
  verificationTokenRepository: VerificationTokenRepository;
  serviceKeyRepository: ServiceKeyRepository;
  credentialRepository: CredentialRepository;
  attemptCounterRepository?: AttemptCounterRepository; // optional (0.3.0)
}
```

## Plugging in a custom adapter — `config.storage.factory`

```ts
storage?: {
  factory?: (
    resolvedConfig: IdpConfig,
    deps: { hashEmail: (email: string) => string; normalizeEmail: (email: string) => string }
  ) => Promise<StorageContract>;
}
```

`factory` has the **exact same signature** as the built-in `createMongoStorage(mongoConfig,
emailDeps)`. This is how a separate adapter package (e.g. `@okeav/idp-core-postgres`) plugs in
**without idp-core ever importing it** — `initIdentityProvider()` calls
`resolved.storage.factory(resolved, { hashEmail, normalizeEmail })` in place of
`createMongoStorage()` when a factory is provided; otherwise it falls back to Mongo unchanged.
`hashEmail`/`normalizeEmail` are handed to your factory so a custom adapter can implement the same
email blind-index pattern the Mongo adapter uses (see below).

## The interfaces

Methods marked "ATOMIC" must be a single conditional write (or a transaction) in your backend: they
are what stops two concurrent requests from both spending the same code, token or counter.

### `UserRepository`
```ts
create(data): Promise<User>
findById(id, opts?: { select?: string }): Promise<User | null>
findByEmail(email, opts?: { select?: string }): Promise<User | null>
findByExternalProvider(provider, providerId): Promise<User | null>
updateById(id, patch, opts?): Promise<User | null>
incrementFailedLoginAttempts(id): Promise<User | null> // atomic $inc, returns post-increment doc
claimTotpStep?(id, step: number): Promise<boolean>        // optional (0.4.0), ATOMIC — see below
consumeRecoveryCode?(id, codeHash: string): Promise<boolean> // optional (0.4.0), ATOMIC — see below
linkExternalProvider(id, link: { provider, providerId, email, connectedAt }): Promise<User>
deleteById(id): Promise<void>
countAll(): Promise<number>
findMany(opts: { skip?: number; limit?: number }): Promise<User[]>
```

- **`claimTotpStep(id, step)`** — set `mfaLastTotpStep = step` only if it is unset or lower;
  resolve whether *this* call set it. This is what stops a TOTP code (including the one that
  confirmed enrolment) from being accepted twice.
- **`consumeRecoveryCode(id, codeHash)`** — set `usedAt` on the one *unused* entry of
  `mfaRecoveryCodes` whose `codeHash` matches; resolve whether one was. Match by hash, never by
  array index (a concurrent regeneration would make an index point at the wrong code).

User fields an adapter must persist (in addition to the profile/status fields it already had):
`mfaLastTotpStep` (number, the last accepted TOTP time step) and `sessionsRevokedAt` (date —
written by logout-all, password reset/change and account deletion *before* the sessions are
revoked; a refresh re-reads it via `findById(id, { select: 'sessionsRevokedAt' })` after writing
its successor row, so a refresh racing "log out everywhere" can't survive it). The user also has a
generic `metadata` object — see
[Storing App-Specific User Data](../examples/consumer-managed-app-data.md).

### `SessionRepository`
```ts
createSession(input): Promise<Session>
findByRefreshTokenHash(hash): Promise<Session | null>
findByJti?(jti): Promise<{ user, expiresAt: Date, revokedAt: Date | null } | null>  // optional (0.3.0) — see below
revokeByRefreshTokenHash(hash, opts?: { onlyIfActive?: boolean; reason?: string }): Promise<Session | null>
revokeFamily?(familyId, opts?: { reason?: string }): Promise<{ revokedCount: number; jtis: string[] }>       // optional (0.4.0)
revokeForClient?(clientId, opts?: { userId?: string }): Promise<{ revokedCount: number; jtis: string[] }>   // optional (0.4.0)
revokeById(id, userId): Promise<Session | null>
revokeAllForUser(userId, opts?: { exceptTokenHash?: string; exceptJti?: string }): Promise<{ revokedCount: number }>
listActiveForUser(userId): Promise<Session[]>
listHistoryForUser(userId, opts?: { limit?: number }): Promise<Session[]>
existsForDevice(userId, fingerprint: string | null, rawDeviceInfo: string): Promise<boolean>  // Mongo adapter: via Model.exists(), which resolves { _id } | null — truthy/falsy-compatible, not a literal boolean
recordIssuedAccessToken?(entry): Promise<void>  // optional, write-only audit
createSessionForLogin(input): Promise<Session>  // atomic composite write — see below
pruneExpired?(): Promise<{ deletedCount: number }>  // optional, for adapters without native TTL
```

**Session row fields (0.4.0).** Persist these as given by `createSession` / `createSessionForLogin`
and return them from `findByRefreshTokenHash` / `revokeByRefreshTokenHash`:

| Field | Meaning |
|---|---|
| `kind` | `'first_party'` (this IdP's own login) or `'oauth2'` (an OAuth2 client's grant; `claims.clientId` names the client). `POST /refresh` accepts only `first_party` rows and the OAuth2 `refresh_token` grant only `oauth2` rows issued to the calling client. Rows without `kind` (written before 0.4.0) are classified by their claims: `{ clientId: string, scopes: [] }` is OAuth2, anything else first-party. |
| `authTime` | When the user actually logged in to start this chain; copied across rotations and emitted as the access token's `auth_time` (used by `requireRecentAuth`). |
| `familyId` | Every row produced by rotating one login's (or one authorization code's — `code:<codeId>`) refresh token shares it. |
| `familyCreatedAt` | Start of the family; no row may outlive `familyCreatedAt + session.absoluteLifetimeSeconds`. |
| `revokeReason` | Written by `revokeByRefreshTokenHash` from `opts.reason` (see below). |

**`revokeByRefreshTokenHash(hash, { onlyIfActive, reason })`** — ATOMIC consume: of two concurrent
callers only one gets the row. Resolves the row **as it was before** revocation. It must persist
`reason` as the row's `revokeReason`: a refresh passes `'rotated'`, and that is how a replayed,
already-rotated token is recognised later (`findByRefreshTokenHash` must return `revokedAt` and
`revokeReason`).

**`revokeFamily(familyId, { reason })`** — revokes every live row with that `familyId` and returns
their `jti`s (which are pushed into the revocation cache). Used when a rotated refresh token is
replayed outside `session.refreshReuseGraceSeconds`, and when an authorization code is redeemed
twice. Without it, reuse is only refused, not punished — the thief's chain lives on.

**`revokeForClient(clientId, { userId? })`** — revokes the live OAuth2 rows issued to `clientId`
(one user's, or every user's when `userId` is omitted) and returns their `jti`s. Used by consent
revocation, client deactivation and `GET /oidc/end-session`. Match pre-0.4.0 rows (no `kind`) by
their `{ clientId, scopes[] }` claims shape, as the Mongo adapter does. Without it, those operations
log a warning and leave the client's tokens working.

**`revokeAllForUser(userId, { exceptTokenHash, exceptJti })`** — `exceptJti` (0.4.0) keeps the row
whose `jti` matches: enabling MFA signs out every *other* session of the account. An adapter that
ignores `exceptJti` also signs out the session that just enrolled.

**`findByJti(jti)`** returns the session whose `jti` matches an access token's `jti` (each session
row stores its paired access token's `jti`). `authContextMiddleware` calls it on **every
authenticated request** while `config.session.verifyOnEachRequest` is on (the default), so it must
be an indexed lookup (Mongo: `{ jti: 1 }`; `@okeav/idp-core-postgres`: `idp_sessions_jti_idx`).
`user` is compared with the token's `sub` via `String()`; return `null` for no match; throw only on
a real backend failure (→ 503 `SESSION_STORE_UNAVAILABLE`). Without it, the middleware falls back
to the per-process revocation cache, with a startup warning — logout-all and password reset then
don't revoke access tokens before they expire. See [Middleware](middleware.md).

### `AuthorizationCodeRepository`
```ts
create(input): Promise<void>
consumeByCodeHash(hash): Promise<AuthCode | null>  // ATOMIC find-and-consume, single-use
findUsedByCodeHash?(hash): Promise<AuthCode | null>  // optional (0.4.0)
pruneExpired?(): Promise<{ deletedCount: number }>
```
Codes now also carry `nonce` (OIDC, from `/authorize`, echoed into the ID token) and `authTime` —
persist both. **`findUsedByCodeHash(hash)`** returns a code that was *already* redeemed (null for an
unknown or still-unused one), so keep consumed codes until they expire rather than deleting them on
use. When a code is presented a second time, everything its first redemption issued (session family
`code:<id of the code>`) is revoked and `OAUTH2_CODE_REUSE_DETECTED` is audited. Without it, a
second redemption is only refused.

### `ConsentRepository`
```ts
upsert(userId, clientId, scopes: string[]): Promise<Consent>
find(userId, clientId): Promise<Consent | null>
listForUser(userId): Promise<Consent[]>
revoke(userId, clientId): Promise<void>
```

### `OAuthClientRepository`
```ts
create(input): Promise<Client>
findByClientId(clientId, opts?: { includeSecret?: boolean }): Promise<Client | null>
findBySlug(slug): Promise<Client | null>
updateByClientId(clientId, patch): Promise<Client>
listMany(opts: { skip?: number; limit?: number }): Promise<Client[]>
countAll(): Promise<number>
```
`clientSecretHash` is an opaque string to the adapter. New secrets are stored as
`hmac-sha256:<hex>` (keyed by `security.tokenHashSecret`); bcrypt hashes from before 0.4.0 still
verify and are replaced through `updateByClientId(clientId, { clientSecretHash })` on their next
successful use — so `updateByClientId` must accept that field.

### `VerificationTokenRepository`
```ts
create(kind: 'password_reset' | 'email_verification' | 'magic_link', input): Promise<void>
consumeByHash(kind, hash, userId?): Promise<Token | null>
consumeByCode(kind, code, userId): Promise<Token | null>
deleteAllForUser(kind, userId): Promise<void>
pruneExpired?(): Promise<{ deletedCount: number }>
```
One repository backs all three token kinds — `email_verification` additionally supports a 6-digit
numeric code alongside the opaque token hash; `password_reset` and `magic_link` are hash-only.
Both consume methods must be ATOMIC and honour `expiresAt`.

Since 0.4.0 the email-verification `verificationCode` is stored as an HMAC (keyed by
`security.tokenHashSecret`), not the 6 digits, so `consumeByCode` is called with that HMAC — it is
an exact-match lookup, nothing more. (Codes issued before 0.4.0 were stored in plain text; the
verify endpoint tries the raw code as a second lookup until they expire.) `deleteAllForUser` is now
used more: a new reset request, a completed reset, a new magic link, a re-registration, and an
exhausted verification-code budget all invalidate the earlier tokens of that kind.

### `ServiceKeyRepository`
```ts
upsertByKid(input: { kid, name, publicKey, region }): Promise<ServiceKey>  // (re)sets status ACTIVE
listPublishable(): Promise<ServiceKey[]>  // every ACTIVE/ROTATING service key
findPublishableByKid?(kid): Promise<ServiceKey | null>  // optional (0.4.0) — indexed single-key read
setStatusByKid(kid, status: 'ROTATING' | 'RETIRED' | 'REVOKED'): Promise<ServiceKey | null>  // required (0.4.0)
```
`setStatusByKid` backs key rotation and `revokeServiceKey()` (return `null` for an unknown `kid`).
`findPublishableByKid` serves in-process S2S token verification; without it, every verification
scans `listPublishable()`. See [Service Mesh](service-mesh.md).

### `CredentialRepository` (WebAuthn)
```ts
create(input: { userId, credentialId, publicKey, counter, transports?, deviceType?, backedUp?, name? }): Promise<Credential>
findByCredentialId(credentialId): Promise<Credential | null>
findByUserId(userId): Promise<Credential[]>
updateCounter(credentialId, newCounter): Promise<boolean>        // ATOMIC conditional write (0.4.0)
deleteByCredentialId(credentialId, userId): Promise<boolean>     // scoped to the claimed owner; resolves whether one was deleted
countForUser(userId): Promise<number>
```
`credentialId` is the base64url credential ID from the browser (globally unique per WebAuthn spec)
and is the natural lookup key during both passwordless and MFA-second-factor authentication.

**`updateCounter`** must write only if the counter moved forward — `counter < newCounter` — or, for
an authenticator that doesn't implement a counter, `newCounter === 0` and the stored counter is
still `0`; resolve whether it wrote. A `false` fails the assertion, so of two concurrent uses of
one signed assertion only one gets through. (An adapter resolving `undefined`, as before 0.4.0, is
treated as success — and loses that protection.) `findByUserId` backs the new `GET /me/passkeys`.

### `AttemptCounterRepository` (optional)
```ts
get(key): Promise<{ count: number, windowExpiresAt: Date, lockedUntil: Date | null } | null>
recordFailure(key, opts: { max: number, windowSeconds: number, lockSeconds: number }): Promise<{ count, windowExpiresAt, lockedUntil }>
reset(key): Promise<void>
pruneExpired?(): Promise<{ deletedCount: number }>
```
Fixed-window counters with a lock, keyed by an opaque string. Lives in storage rather than the rate
limiter so every instance sees the same count whatever cache/rate-limiter adapter is configured.
Current keys:

- `mfa:<userId>` — the [per-account MFA lockout](mfa.md#per-account-lockout);
- `email-verification:<userId>` — the per-account email-verification code budget
  (`security.verificationCodeLockout`);
- `mfa-challenge-used:<jti>` — marks an MFA challenge token spent (`max: 1`), so it completes one
  login only.

Despite its name, `recordFailure` is called **before** the secret is checked: the atomic increment
is the gate, so a burst of concurrent requests gets exactly `max` guesses; a success then calls
`reset`. It must be **atomic**: if there's no record, or (with no lock still active) its window has
passed or its lock has expired, start over at `count: 1` with a new window; otherwise `count + 1`.
When the count reaches `max` and no lock is set, set `lockedUntil = now + lockSeconds`. Return the
post-update record. Concurrent callers must each see a distinct count (exactly one sees
`count === max`). An error thrown from any method fails the attempt closed.

Without it, `initIdentityProvider()` substitutes an in-process counter and logs a warning — correct
for one instance, but each instance of a scaled deployment then keeps its own counts (and its own
record of spent challenge tokens). `@okeav/idp-core-postgres` 0.2.0 implements both this and
`findByJti` (its `0002_` migration adds the `idp_attempt_counters` table); the MSSQL and DynamoDB
adapters don't yet and get the fallbacks.

## Optional methods and their fallbacks

| Method | Since | Without it |
|---|---|---|
| `attemptCounterRepository` | 0.3.0 | In-process counters (MFA lockout, verification-code budget, spent MFA challenge tokens) — per instance. **Startup warning.** |
| `SessionRepository.findByJti` | 0.3.0 | Per-process revocation cache only; logout-all/password reset don't revoke access tokens before they expire. **Startup warning** (when `verifyOnEachRequest` is on). |
| `UserRepository.claimTotpStep` / `consumeRecoveryCode` | 0.4.0 | Non-atomic read-then-write — correct sequentially, racy under concurrency. **Startup warning.** |
| `SessionRepository.revokeFamily` | 0.4.0 | Refresh-token and authorization-code reuse is refused but nothing else is revoked. |
| `SessionRepository.revokeForClient` | 0.4.0 | Consent revocation / client deactivation leave the client's tokens working (warning logged each time); end-session skips them. |
| `AuthorizationCodeRepository.findUsedByCodeHash` | 0.4.0 | A redeemed code presented again is refused, but its tokens aren't revoked. |
| `ServiceKeyRepository.findPublishableByKid` | 0.4.0 | S2S verification scans `listPublishable()`. |

Changed **required** behaviour in 0.4.0, with no fallback: persist the new session fields (`kind`,
`authTime`, `familyId`, `familyCreatedAt`, `revokeReason`) and `revokeByRefreshTokenHash`'s
`reason`; honour `revokeAllForUser`'s `exceptJti`; persist `nonce`/`authTime` on authorization
codes and `mfaLastTotpStep`/`sessionsRevokedAt` on users; implement `ServiceKeyRepository.setStatusByKid`;
make `CredentialRepository.updateCounter` and `deleteByCredentialId` conditional writes that resolve
a boolean. A custom **cache** adapter also needs the new atomic `take()` — see
[Cache Interface](cache-interface.md).

## The built-in MongoDB adapter

`createMongoStorage(mongoConfig, { hashEmail, normalizeEmail })` (`src/storage/mongo/index.js`):

```ts
mongo: { uri: string } | { connection: MongooseConnection }, plus { skipTransactionCheck?: boolean }
```

Creates a **dedicated Mongoose connection** (`mongoose.createConnection(uri)`) — never mutates the
global `mongoose.connection`, so it coexists with a consumer app that also uses Mongoose for its
own models. It implements every optional method above.

### Email storage: blind index + plaintext

`MongoUserRepository.findByEmail` queries `{ $or: [{ emailHash: hashEmail(normalized) }, { email:
normalized }] }` — the plaintext `email` field is kept for display/OIDC claims/outbound mail, but
lookups also match on `emailHash`, an HMAC-SHA256 blind index keyed by
`config.security.emailHashPepper`. This lets a leaked database (without the pepper) resist being
brute-forced for common addresses. **The pepper must be treated as a non-rotating, well-backed-up
secret** — rotating it invalidates every existing user's email lookup hash. Both fields are indexed
(the `{ email: 1 }` index is new in 0.4.0 — without it the `email` branch of the `$or` scanned the
whole collection on every lookup); Mongoose builds it on startup unless you've turned `autoIndex`
off, in which case create it yourself.

### Transactions are required

`SessionRepository.createSessionForLogin()` — the atomic "write session + audit record + update
`lastLoginAt`" used by login, MFA-verify, SSO callback, magic-link verify, and WebAuthn login —
uses a real Mongo transaction (`connection.startSession().withTransaction()`). This requires your
MongoDB deployment to be a **replica set** (a single-node one is enough) or a sharded cluster — a
standalone `mongod` cannot run it.

`initIdentityProvider()` checks this at **startup** (a real, read-only, no-op transaction) rather
than letting it surface as a confusing failure on someone's first login. If unsupported, it throws
`IdpError({ code: 'MONGO_TRANSACTIONS_UNSUPPORTED', httpStatus: 500 })` with the fix inline: use
the package repo's `docker-compose.yml` for local dev (single-node replica set,
`rs.initiate()` already run), or convert an existing standalone `mongod` in place — restart with
`--replSet rs0`, connect once, run `rs.initiate()` (existing data preserved, no reinstall). Set
`mongo.skipTransactionCheck: true` to skip this startup probe (e.g. a CI job reusing a known-good
cluster).

### Ten Mongoose models (backing nine repositories)

`identity-user`, `session` (+ a separate `access-token-audit` model for write-only audit records),
`authorization-code`, `consent`, `oauth-client`, `verification-token`, `service-key`, `credential`,
`attempt-counter` (collection model `IdpAttemptCounter`, unique on `key`, TTL index on
`expiresAt`) — one per repository (session backs two models). All registered on the dedicated
connection via `defineXModel(connection, ...)` factories. The session model's `{ jti: 1 }` index
serves `findByJti`, and `{ familyId: 1, revokedAt: 1 }` serves `revokeFamily`.

## Related

- [Bootstrap & Config](bootstrap-config.md) — `config.mongo`/`config.storage`.
- [Password & Email Auth](password-email-auth.md), [Magic Link](magic-link.md),
  [WebAuthn](webauthn.md) — the primary consumers of these repositories.
- [Custom Mongo Repository Adapter example](../examples/custom-mongo-repository-adapter.md)
