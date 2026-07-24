/**
 * Storage interfaces — documentation only (JS has no runtime interface
 * checks). See types/index.d.ts for the enforced TypeScript shapes.
 *
 * This file exists so every Mongo repository can `@implements` a named
 * interface, and so a future non-Mongo adapter has a single place to read
 * the full contract it must satisfy. All 8 repositories are returned
 * together from a `createXStorage(config, {hashEmail, normalizeEmail})`
 * factory (see mongo/index.js for the MongoDB one) — a non-Mongo adapter
 * exports the same factory shape and can be wired in via
 * `config.storage.factory` (see config/init.js) without idp-core ever
 * importing it. The returned object must also include a `close(): Promise<void>`
 * for adapter-agnostic teardown — `connection` (as returned by the Mongo
 * adapter) is adapter-specific and optional; a Postgres/DynamoDB/etc.
 * adapter has no equivalent raw handle to expose there, `close()` is the
 * one teardown method every adapter must provide.
 *
 * @typedef {Object} UserRepository
 * @property {(data: object) => Promise<object>} create
 * @property {(id: string, opts?: {select?: string}) => Promise<object|null>} findById
 * @property {(email: string, opts?: {select?: string}) => Promise<object|null>} findByEmail
 * @property {(provider: string, providerId: string) => Promise<object|null>} findByExternalProvider
 * @property {(id: string, patch: object, opts?: object) => Promise<object|null>} updateById
 * @property {(id: string) => Promise<object|null>} incrementFailedLoginAttempts - atomic $inc, returns the post-increment document
 * @property {(id: string, link: {provider, providerId, email, connectedAt}) => Promise<object>} linkExternalProvider
 * @property {(id: string) => Promise<void>} deleteById
 * @property {() => Promise<number>} countAll
 * @property {(opts: {skip?: number, limit?: number}) => Promise<object[]>} findMany
 *
 * @typedef {Object} SessionRepository
 * @property {(input: object) => Promise<object>} createSession
 * @property {(hash: string) => Promise<object|null>} findByRefreshTokenHash
 * @property {(hash: string, opts?: {onlyIfActive?: boolean}) => Promise<object|null>} revokeByRefreshTokenHash
 * @property {(id: string, userId: string) => Promise<object|null>} revokeById
 * @property {(userId: string, opts?: {exceptTokenHash?: string}) => Promise<{revokedCount: number}>} revokeAllForUser
 * @property {(userId: string) => Promise<object[]>} listActiveForUser
 * @property {(userId: string, opts?: {limit?: number}) => Promise<object[]>} listHistoryForUser
 * @property {(userId: string, fingerprint: string|null, rawDeviceInfo: string) => Promise<boolean>} existsForDevice
 * @property {(entry: object) => Promise<void>} [recordIssuedAccessToken] - optional, write-only audit
 * @property {(input: object) => Promise<object>} createSessionForLogin - atomic composite write, see §2.1
 * @property {() => Promise<{deletedCount: number}>} [pruneExpired] - optional, for adapters without native TTL
 *
 * @typedef {Object} AuthorizationCodeRepository
 * @property {(input: object) => Promise<void>} create
 * @property {(hash: string) => Promise<object|null>} consumeByCodeHash
 * @property {() => Promise<{deletedCount: number}>} [pruneExpired]
 *
 * @typedef {Object} ConsentRepository
 * @property {(userId: string, clientId: string, scopes: string[]) => Promise<object>} upsert
 * @property {(userId: string, clientId: string) => Promise<object|null>} find
 * @property {(userId: string) => Promise<object[]>} listForUser
 * @property {(userId: string, clientId: string) => Promise<void>} revoke
 *
 * @typedef {Object} OAuthClientRepository
 * @property {(input: object) => Promise<object>} create
 * @property {(clientId: string, opts?: {includeSecret?: boolean}) => Promise<object|null>} findByClientId
 * @property {(slug: string) => Promise<object|null>} findBySlug
 * @property {(clientId: string, patch: object) => Promise<object>} updateByClientId
 * @property {(opts: {skip?: number, limit?: number}) => Promise<object[]>} listMany
 * @property {() => Promise<number>} countAll
 *
 * @typedef {Object} VerificationTokenRepository
 * @property {(kind: 'password_reset'|'email_verification'|'magic_link', input: object) => Promise<void>} create
 * @property {(kind: string, hash: string, userId?: string) => Promise<object|null>} consumeByHash
 * @property {(kind: string, code: string, userId: string) => Promise<object|null>} consumeByCode
 * @property {(kind: string, userId: string) => Promise<void>} deleteAllForUser
 * @property {() => Promise<{deletedCount: number}>} [pruneExpired]
 *
 * @typedef {Object} ServiceKeyRepository
 * @property {(input: {kid, name, publicKey, region}) => Promise<object>} upsertByKid
 * @property {() => Promise<object[]>} listPublishable
 *
 * @typedef {Object} CredentialRepository
 * WebAuthn/passkey credentials — one document per registered authenticator.
 * `credentialId` is the base64url credential ID from the browser (globally
 * unique per WebAuthn spec) and is the natural lookup key during both the
 * primary-passwordless and MFA-second-factor authentication ceremonies.
 * @property {(input: {userId, credentialId, publicKey, counter, transports?, deviceType?, backedUp?, name?}) => Promise<object>} create
 * @property {(credentialId: string) => Promise<object|null>} findByCredentialId
 * @property {(userId: string) => Promise<object[]>} findByUserId
 * @property {(credentialId: string, newCounter: number) => Promise<void>} updateCounter
 * @property {(credentialId: string, userId: string) => Promise<void>} deleteByCredentialId - scoped to the claimed owner
 * @property {(userId: string) => Promise<number>} countForUser
 */
export {};
