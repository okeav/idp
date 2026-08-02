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

  return {
    close: async () => { users.clear(); },
    userRepository,
    // ...the other seven repositories
  };
}

await initIdentityProvider({
  issuer: 'http://localhost:3000',
  storage: { factory: createInMemoryStorage }, // no config.mongo needed at all
  signingKeys: { keys: { k1: { privateKey, publicKey, status: 'ACTIVE' } } },
  security: { emailHashPepper: '...', tokenHashSecret: '...' },
});
```

Note `mongo.skipTransactionCheck` and the whole Mongo-transaction-support startup probe (see
[Repository Adapters](../api/repository-adapters.md#transactions-are-required)) only apply to the
**built-in** Mongo adapter — a custom `storage.factory` is never subject to that check; your
adapter is responsible for whatever atomicity guarantees it needs on its own.

## Related

- [Repository Adapters](../api/repository-adapters.md) — the full eight-interface contract.
- [Bootstrap & Config](../api/bootstrap-config.md) — `config.storage`/`config.mongo`.
