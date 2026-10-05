---
title: "Storing App-Specific User Data (Roles, Capabilities, Profile Fields)"
package: "@okeav/idp-core"
category: "example"
tags: ["hooks", "resolveAuthContext", "rbac", "custom-fields"]
description: "The canonical pattern for attaching app-specific fields to a user — role, capabilities, display name, anything idp-core doesn't know about — without touching idp-core's own User schema."
---

# Storing App-Specific User Data (Roles, Capabilities, Profile Fields)

`@okeav/idp-core`'s `User` record is deliberately fixed — email, failed-login counters, linked
external providers, and the handful of other fields every identity flow needs. It has **no
generic `profile`/`metadata` bag** for your application's own fields (a `role`, an RBAC
`capabilities` array, a display name, anything domain-specific). That's not an oversight — this
package stays an identity layer, not an accounts/profile store, so it never needs an opinion on
your data model. See [Bootstrap & Config](../api/bootstrap-config.md#claims-are-opaque): "claims
are opaque," and the package "ships no scope-matching or permission-checking logic" — the same
principle extends to the account record itself.

## The pattern: a consumer-owned collection, joined by `user.id`

Don't reach into idp-core's own Mongo documents (that's the *escape hatch*, covered below) — keep
a separate collection in your own app, keyed by the `id` idp-core already gives you, and populate
it inside `hooks.resolveAuthContext`. idp-core's Mongo adapter uses a dedicated
`mongoose.createConnection()` that "never mutates the global `mongoose.connection`" (see
[Repository Adapters](../api/repository-adapters.md#the-built-in-mongodb-adapter)), specifically
so a consumer app can run its own Mongoose models — or any other database entirely — alongside it
without conflict.

```js
import mongoose from 'mongoose';
import { initIdentityProvider, buildRouter, cookieParser } from '@okeav/idp-core';

// Your own model, your own connection — nothing to do with idp-core's storage layer.
const Account = mongoose.model('Account', new mongoose.Schema({
  userId: { type: String, required: true, unique: true }, // idp-core's user.id
  capabilities: { type: [String], default: [] },
}));

await mongoose.connect(process.env.APP_MONGO_URI); // separate connection/URI from idp-core's own

await initIdentityProvider({
  issuer: 'https://auth.example.com',
  mongo: { uri: process.env.IDP_MONGO_URI },
  signingKeys: { keys: { /* ... */ } },
  security: { emailHashPepper: '...', tokenHashSecret: '...' },
  mfa: { encryptionKey: process.env.IDP_MFA_ENCRYPTION_KEY },

  hooks: {
    // Called on every login that mints a session (password, MFA-verify, SSO, magic-link,
    // WebAuthn) — see the Event hooks table in Bootstrap & Config for the full list.
    resolveAuthContext: async (user, ctx) => {
      let account = await Account.findOne({ userId: user.id });

      // First login ever for this user — create the app-side record with your defaults.
      if (!account) {
        account = await Account.create({ userId: user.id, capabilities: ['READER'] });
      }

      return {
        claims: {
          accountType: 'PLATFORM',
          role: 'MEMBER',              // a constant here if your app has no role axis to speak of
          capabilities: account.capabilities,
        },
      };
    },
  },
});
```

`resolveAuthContext` is the one hook idp-core does **not** swallow errors from — a throwing lookup
here fails the login request itself rather than silently issuing a token with no claims (see
[Bootstrap & Config](../api/bootstrap-config.md#event-hooks-confighooks)). That's the correct
behavior for RBAC fields: an unresolvable account record should block the session, not hand out
an empty-permissions token silently.

## Why not just add the field to idp-core's own user document?

You can — [Extending a Mongo Repository](custom-mongo-repository-adapter.md) documents decorating
the built-in `userRepository` to write directly to idp-core's own Mongoose model when you
genuinely need the field to live on that document (e.g. it must be visible in an admin tool built
directly against idp-core's schema). For everything else, a separate collection is the better
default:

- **No coupling to idp-core's internal schema.** `userRepository.model` is reached into directly
  by the decorator pattern — an implementation detail, not a stable contract you should build
  business logic against.
- **Survives a storage-adapter swap.** Move to `@okeav/idp-core-postgres` or
  `@okeav/idp-core-dynamodb` later and your `Account` collection doesn't move with it — it was
  never part of idp-core's storage in the first place.
- **Matches how permission libraries expect to consume claims.** e.g.
  [`@okeav/rbac-core`'s `fromClaims`](https://github.com/okeav/rbac) adapts exactly the flat
  `{ accountType, role, capabilities }` shape `resolveAuthContext` returns above — see its
  [idp-core integration guide](https://github.com/okeav/rbac/blob/main/docs/examples/idp-core-integration.md)
  for wiring the resulting access-token claims into route guards.

## Related

- [Bootstrap & Config](../api/bootstrap-config.md) — `hooks.resolveAuthContext`, the full event
  hooks table, and "Claims are opaque."
- [Repository Adapters](../api/repository-adapters.md) — why idp-core's Mongo connection is safe
  to run alongside your own Mongoose models.
- [Extending a Mongo Repository](custom-mongo-repository-adapter.md) — the escape hatch, if you
  need the field on idp-core's own user document instead.
- `@okeav/rbac-core`'s
  [Wiring Up with @okeav/idp-core](https://github.com/okeav/rbac/blob/main/docs/examples/idp-core-integration.md) —
  what to do with these claims once they reach an access token.
