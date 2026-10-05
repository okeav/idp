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
interfaces; nothing above the storage layer needs to change. Two newer pieces are optional —
`SessionRepository.findByJti` and `attemptCounterRepository` (both 0.3.0) — and an adapter without
them still boots, with a startup warning and a weaker fallback (see below).

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

### `UserRepository`
```ts
create(data): Promise<User>
findById(id, opts?: { select?: string }): Promise<User | null>
findByEmail(email, opts?: { select?: string }): Promise<User | null>
findByExternalProvider(provider, providerId): Promise<User | null>
updateById(id, patch, opts?): Promise<User | null>
incrementFailedLoginAttempts(id): Promise<User | null> // atomic $inc, returns post-increment doc
linkExternalProvider(id, link: { provider, providerId, email, connectedAt }): Promise<User>
deleteById(id): Promise<void>
countAll(): Promise<number>
findMany(opts: { skip?: number; limit?: number }): Promise<User[]>
```

### `SessionRepository`
```ts
createSession(input): Promise<Session>
findByRefreshTokenHash(hash): Promise<Session | null>
findByJti?(jti): Promise<{ user, expiresAt: Date, revokedAt: Date | null } | null>  // optional (0.3.0) — see below
revokeByRefreshTokenHash(hash, opts?: { onlyIfActive?: boolean }): Promise<Session | null>
revokeById(id, userId): Promise<Session | null>
revokeAllForUser(userId, opts?: { exceptTokenHash?: string }): Promise<{ revokedCount: number }>
listActiveForUser(userId): Promise<Session[]>
listHistoryForUser(userId, opts?: { limit?: number }): Promise<Session[]>
existsForDevice(userId, fingerprint: string | null, rawDeviceInfo: string): Promise<boolean>  // Mongo adapter: via Model.exists(), which resolves { _id } | null — truthy/falsy-compatible, not a literal boolean
recordIssuedAccessToken?(entry): Promise<void>  // optional, write-only audit
createSessionForLogin(input): Promise<Session>  // atomic composite write — see below
pruneExpired?(): Promise<{ deletedCount: number }>  // optional, for adapters without native TTL
```

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
consumeByCodeHash(hash): Promise<AuthCode | null>  // atomic find-and-consume, single-use
pruneExpired?(): Promise<{ deletedCount: number }>
```

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

### `ServiceKeyRepository`
```ts
upsertByKid(input: { kid, name, publicKey, region }): Promise<ServiceKey>
listPublishable(): Promise<ServiceKey[]>  // every ACTIVE/ROTATING service key
```

### `CredentialRepository` (WebAuthn)
```ts
create(input: { userId, credentialId, publicKey, counter, transports?, deviceType?, backedUp?, name? }): Promise<Credential>
findByCredentialId(credentialId): Promise<Credential | null>
findByUserId(userId): Promise<Credential[]>
updateCounter(credentialId, newCounter): Promise<void>
deleteByCredentialId(credentialId, userId): Promise<void>  // scoped to the claimed owner
countForUser(userId): Promise<number>
```
`credentialId` is the base64url credential ID from the browser (globally unique per WebAuthn spec)
and is the natural lookup key during both passwordless and MFA-second-factor authentication.

### `AttemptCounterRepository` (optional)
```ts
get(key): Promise<{ count: number, windowExpiresAt: Date, lockedUntil: Date | null } | null>
recordFailure(key, opts: { max: number, windowSeconds: number, lockSeconds: number }): Promise<{ count, windowExpiresAt, lockedUntil }>
reset(key): Promise<void>
pruneExpired?(): Promise<{ deletedCount: number }>
```
Fixed-window failure counters with a lock, keyed by an opaque string (currently `mfa:<userId>` —
the [per-account MFA lockout](mfa.md#per-account-lockout)). Lives in storage rather than the rate
limiter so every instance sees the same count whatever cache/rate-limiter adapter is configured.

`recordFailure` must be **atomic**: if there's no record, or (with no lock still active) its window
has passed or its lock has expired, start over at `count: 1` with a new window; otherwise
`count + 1`. When the count reaches `max` and no lock is set, set `lockedUntil = now +
lockSeconds`. Return the post-update record. Concurrent callers must each see a distinct count
(exactly one sees `count === max` — that one emits the `MFA_LOCKED` audit event). An error thrown
from any method fails the MFA attempt closed.

Without it, `initIdentityProvider()` substitutes an in-process counter and logs a warning — correct
for one instance, but each instance of a scaled deployment then keeps its own count.
`@okeav/idp-core-postgres` 0.2.0 implements both this and `findByJti` (its `0002_` migration adds
the `idp_attempt_counters` table); the MSSQL and DynamoDB adapters don't yet and get the fallbacks.

## The built-in MongoDB adapter

`createMongoStorage(mongoConfig, { hashEmail, normalizeEmail })` (`src/storage/mongo/index.js`):

```ts
mongo: { uri: string } | { connection: MongooseConnection }, plus { skipTransactionCheck?: boolean }
```

Creates a **dedicated Mongoose connection** (`mongoose.createConnection(uri)`) — never mutates the
global `mongoose.connection`, so it coexists with a consumer app that also uses Mongoose for its
own models.

### Email storage: blind index + plaintext

`MongoUserRepository.findByEmail` queries `{ $or: [{ emailHash: hashEmail(normalized) }, { email:
normalized }] }` — the plaintext `email` field is kept for display/OIDC claims/outbound mail, but
lookups also match on `emailHash`, an HMAC-SHA256 blind index keyed by
`config.security.emailHashPepper`. This lets a leaked database (without the pepper) resist being
brute-forced for common addresses. **The pepper must be treated as a non-rotating, well-backed-up
secret** — rotating it invalidates every existing user's email lookup hash.

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
serves `findByJti`.

## Related

- [Bootstrap & Config](bootstrap-config.md) — `config.mongo`/`config.storage`.
- [Password & Email Auth](password-email-auth.md), [Magic Link](magic-link.md),
  [WebAuthn](webauthn.md) — the primary consumers of these repositories.
- [Custom Mongo Repository Adapter example](../examples/custom-mongo-repository-adapter.md)
