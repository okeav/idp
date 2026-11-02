---
title: "Extending a Mongo Repository / Building a Custom Storage Adapter"
package: "@okeav/idp-core"
category: "example"
tags: ["mongodb", "storage-adapter", "repository"]
description: "Two patterns: wrapping a built-in Mongo repository to add custom fields/behavior, and the full config.storage.factory contract for a non-Mongo adapter."
---

# Extending a Mongo Repository / Building a Custom Storage Adapter

Two different needs, two different patterns. See [Repository Adapters](../api/repository-adapters.md)
for the full eight-interface contract both patterns must satisfy.

## Prerequisites

- Familiarity with the `UserRepository` interface (or whichever repository you're extending) in
  [Repository Adapters](../api/repository-adapters.md).
- A MongoDB replica set for pattern 1 (see [Quickstart](quickstart-express.md)).

## Pattern 1: wrap a built-in Mongo repository to add behavior

You don't need `config.storage.factory` to customize *behavior* around the existing Mongo
adapter — `initIdentityProvider()`'s return value exposes the wired `storage` object, so you can
decorate one repository after init and keep using it directly in your own routes (this doesn't
change what idp-core's own handlers do internally — they always use the repositories built at
init time — but it's the right pattern for *your own* code that reads/writes the same collections,
e.g. adding a custom `lastSeenAt` field update on every authenticated request).

```js
import { initIdentityProvider } from '@okeav/idp-core';

const { storage } = await initIdentityProvider({ /* ...config */ });

const baseUserRepo = storage.userRepository;

// A thin decorator adding one custom write, delegating everything else unchanged.
//
// NOTE: the built-in repositories implement their methods (findById, create, ...)
// on the class prototype, not as own instance properties — only a handful of
// internals (model, _hashEmail, _normalizeEmail) are set per-instance. A plain
// object spread (`{ ...baseUserRepo, touchLastSeen(...) {...} }`) only copies own
// enumerable properties, so it silently drops every prototype method and leaves
// you with an object that can *only* touchLastSeen. Use Object.create() instead
// so property/method lookups still fall through to baseUserRepo's prototype chain:
const userRepoWithLastSeen = Object.create(baseUserRepo);
userRepoWithLastSeen.touchLastSeen = async function touchLastSeen(userId) {
  // Reach into the underlying Mongoose model directly for a field idp-core
  // doesn't know about — safe as long as you don't touch fields idp-core owns.
  return baseUserRepo.model.findByIdAndUpdate(userId, { $set: { lastSeenAt: new Date() } });
};

// Use userRepoWithLastSeen.touchLastSeen(...) in your own middleware — idp-core's
// own handlers (loginHandler, getMeHandler, etc.) are unaffected either way.
```

## Pattern 2: a full custom adapter via `config.storage.factory`

Use this when you want a **different database entirely** (Postgres, DynamoDB, an in-memory store
for tests) — `storage.factory` is called in place of the built-in `createMongoStorage`, with the
exact same signature, and idp-core never imports Mongo-specific code when a factory is provided.

```ts
storage?: {
  factory?: (
    resolvedConfig: IdpConfig,
    deps: { hashEmail: (email: string) => string; normalizeEmail: (email: string) => string }
  ) => Promise<StorageContract>;
}
```

A minimal (illustrative, not production-ready) in-memory adapter implementing just enough of
`UserRepository` and `SessionRepository` to show the shape — a real adapter implements all eight
interfaces from [Repository Adapters](../api/repository-adapters.md):

```js
function createInMemoryStorage(config, { hashEmail, normalizeEmail }) {
  const users = new Map();
  let nextId = 1;

  const userRepository = {
    async create(data) {
      const id = String(nextId++);
      const email = normalizeEmail(data.email);
      const user = { id, ...data, email, emailHash: hashEmail(email), createdAt: new Date(), updatedAt: new Date() };
      users.set(id, user);
      return user;
    },
    async findById(id) {
      return users.get(id) || null;
    },
    async findByEmail(email) {
      const hash = hashEmail(normalizeEmail(email));
      for (const user of users.values()) if (user.emailHash === hash) return user;
      return null;
    },
    async findByExternalProvider() { return null; }, // implement if you support SSO
    async updateById(id, patch) {
      const user = users.get(id);
      if (!user) return null;
      Object.assign(user, patch, { updatedAt: new Date() });
      return user;
    },
    async incrementFailedLoginAttempts(id) {
      const user = users.get(id);
      if (!user) return null;
      user.failedLoginAttempts = (user.failedLoginAttempts || 0) + 1;
      return user;
    },
    // Optional but recommended (0.4.0): single-use TOTP steps and recovery codes. In a real
    // database each is ONE conditional update (e.g. UPDATE ... WHERE mfa_last_totp_step IS NULL
    // OR mfa_last_totp_step < $step), never read-then-write. A single-threaded Map is atomic enough.
    async claimTotpStep(id, step) {
      const user = users.get(id);
      if (!user || (user.mfaLastTotpStep != null && user.mfaLastTotpStep >= step)) return false;
      user.mfaLastTotpStep = step;
      return true;
    },
    async consumeRecoveryCode(id, codeHash) {
      const code = users.get(id)?.mfaRecoveryCodes?.find((rc) => rc.codeHash === codeHash && !rc.usedAt);
      if (!code) return false;
      code.usedAt = new Date();
      return true;
    },
    async linkExternalProvider(id, link) {
      const user = users.get(id);
      user.externalProviders = [...(user.externalProviders || []), link];
      return user;
    },
    async deleteById(id) { users.delete(id); },
    async countAll() { return users.size; },
    async findMany({ skip = 0, limit = 20 } = {}) {
      return [...users.values()].slice(skip, skip + limit);
    },
  };

  // sessionRepository, authorizationCodeRepository, consentRepository,
  // oauthClientRepository, verificationTokenRepository, serviceKeyRepository,
  // credentialRepository — same pattern, see repository-adapters.md for each
  // method's exact signature. createSessionForLogin() in particular needs to
  // behave atomically (write session + audit + lastLoginAt together) even
  // without a real transaction, since nothing above the storage layer retries.
  //
  // sessionRepository.findByJti(jti) is optional but strongly recommended: it
  // runs on every authenticated request (session.verifyOnEachRequest), so back
  // it with an index on the session's jti, e.g.
  //   async findByJti(jti) { return sessionsByJti.get(jti) ?? null; } // → { user, expiresAt, revokedAt } | null
  //
  // Since 0.4.0, session rows also carry kind ('first_party' | 'oauth2'), authTime,
  // familyId and familyCreatedAt — store them as given. revokeByRefreshTokenHash must
  // persist opts.reason as revokeReason (and findByRefreshTokenHash return it), and
  // revokeAllForUser must honour opts.exceptJti. Implement revokeFamily(familyId) and
  // revokeForClient(clientId, { userId }) (both → { revokedCount, jtis }) so refresh-token
  // reuse, consent revocation and client deactivation actually revoke tokens.
  // credentialRepository.updateCounter / deleteByCredentialId resolve a boolean
  // (conditional writes), and a custom cache adapter needs an atomic take().

  // Optional: attempt counters — the per-account MFA lockout, the email-verification
  // code budget, and single-use MFA challenge tokens. recordFailure is called BEFORE
  // the secret is checked and must be atomic — in a real database, one conditional
  // upsert, not read-then-write.
  const counters = new Map();
  const attemptCounterRepository = {
    async get(key) { return counters.get(key) ?? null; },
    async recordFailure(key, { max, windowSeconds, lockSeconds }) {
      const now = Date.now();
      const prev = counters.get(key);
      const lockActive = prev?.lockedUntil && prev.lockedUntil.getTime() > now;
      const fresh = !prev || (!lockActive && (prev.windowExpiresAt.getTime() <= now || prev.lockedUntil));
      const entry = fresh
        ? { count: 1, windowExpiresAt: new Date(now + windowSeconds * 1000), lockedUntil: null }
        : { ...prev, count: prev.count + 1 };
      if (entry.count >= max && !entry.lockedUntil) entry.lockedUntil = new Date(now + lockSeconds * 1000);
      counters.set(key, entry);
      return entry;
    },
    async reset(key) { counters.delete(key); },
  };

  return {
    close: async () => { users.clear(); },
    userRepository,
    attemptCounterRepository,
    // ...the other seven repositories
  };
}

await initIdentityProvider({
  issuer: 'http://localhost:3000',
  storage: { factory: createInMemoryStorage }, // no config.mongo needed at all
  signingKeys: { keys: { k1: { privateKey, publicKey, status: 'ACTIVE' } } },
  // Both random, at least 32 characters (checked at startup).
  security: { emailHashPepper: process.env.IDP_EMAIL_HASH_PEPPER, tokenHashSecret: process.env.IDP_TOKEN_HASH_SECRET },
  mfa: { encryptionKey: process.env.IDP_MFA_ENCRYPTION_KEY }, // required while MFA is enabled (the default)
});
```

Leave out `findByJti`, `attemptCounterRepository`, or `claimTotpStep`/`consumeRecoveryCode` and
`initIdentityProvider()` still boots, but logs a warning and falls back: access tokens survive
logout-all/password reset until they expire, the MFA lockout (and the record of spent MFA challenge
tokens) is counted per instance, and TOTP/recovery-code reuse is checked with a racy
read-then-write. Leave out `revokeFamily`, `revokeForClient` or
`authorizationCodeRepository.findUsedByCodeHash` and token reuse is refused but not punished, and
revoking consent or deactivating a client leaves its tokens working. Fine for a single-process
test store; implement all of them for anything real — the full table is in
[Repository Adapters](../api/repository-adapters.md#optional-methods-and-their-fallbacks).

Note `mongo.skipTransactionCheck` and the whole Mongo-transaction-support startup probe (see
[Repository Adapters](../api/repository-adapters.md#transactions-are-required)) only apply to the
**built-in** Mongo adapter — a custom `storage.factory` is never subject to that check; your
adapter is responsible for whatever atomicity guarantees it needs on its own.

## Related

- [Repository Adapters](../api/repository-adapters.md) — the full eight-interface contract, plus
  the optional methods (`findByJti`, `AttemptCounterRepository`, `claimTotpStep`,
  `revokeFamily`, ...) and what happens without each.
- [Bootstrap & Config](../api/bootstrap-config.md) — `config.storage`/`config.mongo`.
- [Storing App-Specific User Data](consumer-managed-app-data.md) — the default pattern for a
  `role`/`capabilities`/profile field (a separate consumer-owned collection), and when the user's
  built-in `metadata` object is enough. Reach for Pattern 1 on this page only when the field
  genuinely needs to live on idp-core's own user document.
