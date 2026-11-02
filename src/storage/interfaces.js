/**
 * Storage interfaces — documentation only (JS has no runtime interface
 * checks). See types/index.d.ts for the enforced TypeScript shapes.
 *
 * This file exists so every Mongo repository can `@implements` a named
 * interface, and so a future non-Mongo adapter has a single place to read
 * the full contract it must satisfy. All 8 required repositories (plus the
 * optional `attemptCounterRepository`) are returned
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
 * @property {(id: string, status: string, patch: object) => Promise<object|null>} updateByIdIfStatus - ATOMIC: apply
 *   `patch` only while the user's status is still `status`; null if it changed (registration/activation races)
 * @property {(id: string) => Promise<object|null>} incrementFailedLoginAttempts - atomic $inc, returns the post-increment document
 * @property {(id: string, step: number) => Promise<boolean>} [claimTotpStep] - ATOMIC: set `mfaLastTotpStep = step`
 *   only if it is unset or lower; resolve whether this call set it. Keeps a TOTP code from being accepted twice.
 *   Optional for now (a non-atomic fallback is used, with a startup warning).
 * @property {(id: string, codeHash: string) => Promise<boolean>} [consumeRecoveryCode] - ATOMIC: set `usedAt` on the
 *   one unused recovery code with this hash; resolve whether one was. Optional for now, as above.
 * @property {(id: string, link: {provider, providerId, email, connectedAt}) => Promise<object>} linkExternalProvider
 * @property {(id: string) => Promise<void>} deleteById
 * @property {() => Promise<number>} countAll
 * @property {(opts: {skip?: number, limit?: number}) => Promise<object[]>} findMany
 *
 * @typedef {Object} SessionRepository
 * @property {(input: object) => Promise<object>} createSession
 * @property {(hash: string) => Promise<object|null>} findByRefreshTokenHash
 * @property {(jti: string) => Promise<{user, expiresAt: Date, revokedAt: Date|null}|null>} [findByJti] - the
 *   session whose `jti` matches an access token's `jti`. Called once per authenticated request when
 *   `config.session.verifyOnEachRequest` is on (the default), so it must be an indexed lookup. Optional
 *   for now: an adapter without it falls back to the per-process revocation cache, with a startup warning.
 * @property {(hash: string, opts?: {onlyIfActive?: boolean, reason?: string}) => Promise<object|null>} revokeByRefreshTokenHash -
 *   ATOMIC consume; resolves the row as it was BEFORE revocation. Must persist `reason` as `revokeReason`
 *   ('rotated' on refresh) — that is how a replayed rotated token is recognised.
 * @property {(familyId: string) => Promise<boolean>} isFamilyRevoked - whether revokeFamily ran for this family
 *   (it must tombstone every row of the family, `familyRevokedAt`, not only revoke the live ones)
 * @property {(familyId: string, opts?: {reason?: string}) => Promise<{revokedCount: number, jtis: string[]}>} [revokeFamily] -
 *   revokes every live row with this `familyId` (refresh-token reuse / authorization-code reuse). Optional for now:
 *   without it, reuse is only refused, not punished.
 * @property {(clientId: string, opts?: {userId?: string}) => Promise<{revokedCount: number, jtis: string[]}>} [revokeForClient] -
 *   revokes a client's live OAuth2 rows (one user's, or all). Used by consent revocation, client deactivation, end-session.
 *   Session rows also carry `kind`, `authTime`, `familyId`, `familyCreatedAt` — persist them as given.
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
 * @property {(hash: string) => Promise<object|null>} [findUsedByCodeHash] - an already-redeemed code (for reuse
 *   detection: its first redemption's tokens are revoked). Codes also carry `nonce` and `authTime`.
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
 * @property {(kind: string, by: {tokenHash?: string, verificationCode?: string}, userId: string) => Promise<object|null>} findActive -
 *   a live (unused, unexpired) token WITHOUT consuming it
 * @property {(kind: string, userId: string) => Promise<void>} clearCodes - null the `verificationCode` of every row
 *   (kills guessable codes, keeps unguessable links)
 * @property {(kind: string, userId: string, input: object) => Promise<void>} replaceForUser - ATOMIC: the one live
 *   token of `kind` for the user (password_reset, magic_link), even under concurrent requests
 * @property {(kind: string, userId: string) => Promise<void>} deleteAllForUser
 * @property {() => Promise<{deletedCount: number}>} [pruneExpired]
 *
 * @typedef {Object} ServiceKeyRepository
 * @property {(input: {kid, name, publicKey, region}) => Promise<object|null>} upsertByKid - must return null
 *   (and change nothing) for a kid that is REVOKED — a revoked key is never re-activated
 * @property {(kid: string) => Promise<object|null>} [findByKid] - a key by kid whatever its status (lets a
 *   rotation refuse a revoked key before demoting the current one)
 * @property {() => Promise<object[]>} listPublishable
 * @property {(kid: string) => Promise<object|null>} [findPublishableByKid] - indexed single-key read (verification)
 * @property {(kid: string, status: string, opts?: {expectedStatus?: string}) => Promise<object|null>} setStatusByKid - ROTATING / RETIRED / REVOKED;
 *   with `expectedStatus`, ATOMICALLY only from that status;
 *   should record `statusChangedAt` (a ROTATING key verifies for `serviceMesh.rotationGraceSeconds` after it)
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
 *
 * @typedef {Object} AttemptCounterRepository
 * Optional. Fixed-window failure counters with a lock, keyed by an opaque
 * string (currently `mfa:<userId>` — the per-account second-factor lockout).
 * Lives in storage rather than the rate limiter so every app instance sees
 * the same count whatever cache/rate-limiter adapter is configured. An
 * adapter that doesn't provide it gets an in-process fallback
 * (src/mfa/memory-attempt-counter.js) and a startup warning.
 * @property {(key: string) => Promise<{count: number, windowExpiresAt: Date, lockedUntil: Date|null}|null>} get
 * @property {(key: string, opts: {max: number, windowSeconds: number, lockSeconds: number}) => Promise<{count: number, windowExpiresAt: Date, lockedUntil: Date|null}>} recordFailure -
 *   ATOMIC: if there's no record, or (with no lock still active) its window has passed or its lock has
 *   expired, start over at count 1 with a new window; otherwise count + 1. When the count reaches `max` and no lock is set, set
 *   `lockedUntil = now + lockSeconds`. Returns the post-update record. Concurrent callers must each see a
 *   distinct count (exactly one sees `count === max`).
 * @property {(key: string) => Promise<void>} reset
 * @property {() => Promise<{deletedCount: number}>} [pruneExpired]
 */
export {};
