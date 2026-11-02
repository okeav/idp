---
title: "Storing App-Specific User Data (Roles, Capabilities, Profile Fields)"
package: "@okeav/idp-core"
category: "example"
tags: ["hooks", "resolveAuthContext", "rbac", "custom-fields"]
description: "The canonical pattern for attaching app-specific fields to a user — role, capabilities, display name, anything idp-core doesn't know about — without touching idp-core's own User schema."
---

# Storing App-Specific User Data (Roles, Capabilities, Profile Fields)

`@okeav/idp-core`'s `User` record is deliberately small — email, status, failed-login counters,
linked external providers, and the handful of other fields every identity flow needs. Two parts of
it are open-ended, but neither is the right home for authorization data:

- **`profile`** — `firstName`, `lastName`, `displayName`, `avatarUrl`, `locale`, `zoneinfo`. A
  fixed set of OIDC-style fields, editable by the user through `PATCH /me` (and released in ID
  tokens under the `profile` scope). Nothing else can be added there through the API.
- **`metadata`** — a free-form object (`Record<string, unknown>`, default `{}`), passed to
  `resolveAuthContext` as part of `user`. idp-core never reads or interprets it. `PATCH /me`
  can't write it and `GET /me` doesn't return it; your own server code can set it with
  `storage.userRepository.updateById(user.id, { metadata })` (replacing the whole object).
  `POST /register` **ignores** a `metadata` field in the request body unless you set
  `registration.acceptMetadata: true` — whatever arrives there was written by whoever registered,
  so if you enable it, treat every value as untrusted user input (and note that re-registering a
  still-unverified address keeps the first registration's `metadata`). Before 0.4.0 it was stored
  unconditionally, so any app keeping a role or tenant in it granted that to whoever registered.

So for your application's own fields (a `role`, an RBAC `capabilities` array, anything
domain-specific), the recommendation stays a store you own. That's not an oversight — this package
stays an identity layer, not an accounts/profile store, so it never needs an opinion on your data
model. See [Bootstrap & Config](../api/bootstrap-config.md#claims-are-opaque): "claims are opaque,"
and the package "ships no scope-matching or permission-checking logic" — the same principle extends
to the account record itself. `metadata` is fine for small, non-authoritative values you set
server-side (an external CRM id, a signup source); keep anything that grants access out of it.

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
    // WebAuthn) and — by default since 0.4.0 (session.reresolveClaimsOnRefresh) — on every
    // POST /refresh too (ctx.method === 'refresh'), so a capability change takes effect at the
    // next access-token rotation. Keep it fast. See the Event hooks table in Bootstrap & Config.
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

You can — either in `metadata` (written server-side, never from the registration body — see
above), or as a field of your own: [Extending a Mongo Repository](custom-mongo-repository-adapter.md) documents decorating
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
