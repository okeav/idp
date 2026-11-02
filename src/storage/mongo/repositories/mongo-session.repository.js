import mongoose from 'mongoose';
import { withId, withIds } from '../normalize.js';

/** @implements {import('../../interfaces.js').SessionRepository} */
export class MongoSessionRepository {
    constructor(sessionModel, accessTokenAuditModel, mongooseConnection) {
        this.model = sessionModel;
        this.auditModel = accessTokenAuditModel;
        this.connection = mongooseConnection;
    }

    async createSession(input) {
        return this.model.create(input);
    }

    async findByRefreshTokenHash(hash) {
        return this.model.findOne({ tokenHash: hash });
    }

    /**
     * The per-request check behind `session.verifyOnEachRequest`: a session's
     * `jti` equals its paired access token's `jti`, so this resolves an access
     * token to the session row that decides whether it's still live. Served
     * by the `{ jti: 1 }` index — one indexed read per authenticated request.
     */
    async findByJti(jti) {
        if (!jti) return null;
        const doc = await this.model.findOne({ jti }).select('user expiresAt revokedAt jti familyId createdAt').lean();
        return doc ? withId(doc) : null;
    }

    /** Atomic find+revoke — only one concurrent caller can successfully consume a given refresh token. */
    async revokeByRefreshTokenHash(hash, { onlyIfActive = true, reason = 'revoked' } = {}) {
        const filter = onlyIfActive
            ? { tokenHash: hash, revokedAt: null, expiresAt: { $gt: new Date() } }
            : { tokenHash: hash, revokedAt: null };
        return this.model.findOneAndUpdate(filter, { revokedAt: new Date(), revokeReason: reason }, { returnDocument: 'before' });
    }

    /**
     * Revokes every live row of a refresh-token family, and tombstones the whole family (`familyRevokedAt`
     * on every row, live or not) so a refresh already in flight — whose successor isn't inserted yet —
     * still finds out (isFamilyRevoked). Returns the revoked jtis.
     */
    async revokeFamily(familyId, { reason = 'family_revoked' } = {}) {
        if (!familyId) return { revokedCount: 0, jtis: [] };
        const now = new Date();
        await this.model.updateMany({ familyId, familyRevokedAt: null }, { $set: { familyRevokedAt: now } });
        const filter = { familyId, revokedAt: null };
        const jtis = (await this.model.find(filter).select('jti').lean()).map((d) => d.jti).filter(Boolean);
        const result = await this.model.updateMany(filter, { revokedAt: now, revokeReason: reason });
        return { revokedCount: result.modifiedCount ?? 0, jtis };
    }

    /** Whether the family was revoked as a whole (see revokeFamily). */
    async isFamilyRevoked(familyId) {
        if (!familyId) return false;
        return Boolean(await this.model.exists({ familyId, familyRevokedAt: { $ne: null } }));
    }

    async revokeById(id, userId) {
        if (!mongoose.isValidObjectId(id)) return null;
        return this.model.findOneAndUpdate({ _id: id, user: userId, revokedAt: null }, { revokedAt: new Date() }, { returnDocument: 'after' });
    }

    async revokeAllForUser(userId, { exceptTokenHash, exceptJti } = {}) {
        const filter = { user: userId, revokedAt: null };
        if (exceptTokenHash) filter.tokenHash = { $ne: exceptTokenHash };
        if (exceptJti) filter.jti = { $ne: exceptJti };
        const result = await this.model.updateMany(filter, { revokedAt: new Date() });
        return { revokedCount: result.modifiedCount ?? 0 };
    }

    /**
     * Revokes every live OAuth2 session (refresh-token row) issued to `clientId` — for one user, or
     * for all users when `userId` is omitted (client deactivated). Rows from before 0.4.0 carry no
     * `kind` and are matched by their `{ clientId, scopes[] }` claims shape. Returns the revoked jtis.
     */
    async revokeForClient(clientId, { userId } = {}) {
        const filter = {
            'claims.clientId': clientId,
            revokedAt: null,
            $or: [{ kind: 'oauth2' }, { kind: null, 'claims.scopes': { $type: 'array' } }],
            ...(userId ? { user: userId } : {}),
        };
        const jtis = (await this.model.find(filter).select('jti').lean()).map((d) => d.jti).filter(Boolean);
        const result = await this.model.updateMany(filter, { revokedAt: new Date(), revokeReason: 'client_revoked' });
        return { revokedCount: result.modifiedCount ?? 0, jtis };
    }

    async listActiveForUser(userId) {
        const docs = await this.model
            .find({ user: userId, revokedAt: null, expiresAt: { $gt: new Date() } })
            .select('ipAddress deviceInfo createdAt expiresAt tokenHash')
            .sort({ createdAt: -1 })
            .lean();
        return withIds(docs);
    }

    async listHistoryForUser(userId, { limit = 20 } = {}) {
        const docs = await this.model
            .find({ user: userId })
            .select('ipAddress deviceInfo createdAt expiresAt revokedAt tokenHash')
            .sort({ createdAt: -1 })
            .limit(Math.min(Math.max(limit, 1), 100))
            .lean();
        return withIds(docs);
    }

    async existsForDevice(userId, fingerprint, rawDeviceInfo) {
        return this.model.exists({
            user: userId,
            $or: [...(fingerprint ? [{ deviceFingerprint: fingerprint }] : []), { deviceInfo: rawDeviceInfo }],
        });
    }

    /** Optional — write-only audit trail. No-op-able by an adapter that doesn't want to keep it. */
    async recordIssuedAccessToken(entry) {
        if (!this.auditModel) return;
        await this.auditModel.create(entry);
    }

    /**
     * Composite, atomic "create a login session" operation — wraps the
     * 3-document write (access-token audit + session + user.lastLoginAt)
     * that the audited login/MFA-verify/SSO flows each did inside a Mongo
     * transaction. Exposed as one method so the transaction is this
     * adapter's implementation detail, not something callers orchestrate —
     * a future non-transactional adapter can implement the same method
     * with a different consistency strategy without callers changing.
     */
    async createSessionForLogin({ accessTokenAudit, session, userModel, userId, lastLoginAt }) {
        const mongoSession = await this.connection.startSession();
        try {
            let created;
            await mongoSession.withTransaction(async () => {
                if (accessTokenAudit && this.auditModel) {
                    await this.auditModel.create([accessTokenAudit], { session: mongoSession });
                }
                const [sessionDoc] = await this.model.create([session], { session: mongoSession });
                created = sessionDoc;
                await userModel.findByIdAndUpdate(
                    userId,
                    { $set: { lastLoginAt, failedLoginAttempts: 0, lockUntil: null } },
                    { session: mongoSession }
                );
            });
            return created;
        } finally {
            await mongoSession.endSession();
        }
    }

    /** No-op for the Mongo adapter — the TTL index already deletes expired documents natively. */
    async pruneExpired() {
        return { deletedCount: 0 };
    }
}
