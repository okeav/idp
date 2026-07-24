import { withIds } from '../normalize.js';

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

    /** Atomic find+revoke — only one concurrent caller can successfully consume a given refresh token. */
    async revokeByRefreshTokenHash(hash, { onlyIfActive = true } = {}) {
        const filter = onlyIfActive
            ? { tokenHash: hash, revokedAt: null, expiresAt: { $gt: new Date() } }
            : { tokenHash: hash, revokedAt: null };
        return this.model.findOneAndUpdate(filter, { revokedAt: new Date() }, { returnDocument: 'before' });
    }

    async revokeById(id, userId) {
        return this.model.findOneAndUpdate({ _id: id, user: userId, revokedAt: null }, { revokedAt: new Date() }, { returnDocument: 'after' });
    }

    async revokeAllForUser(userId, { exceptTokenHash } = {}) {
        const filter = { user: userId, revokedAt: null };
        if (exceptTokenHash) filter.tokenHash = { $ne: exceptTokenHash };
        const result = await this.model.updateMany(filter, { revokedAt: new Date() });
        return { revokedCount: result.modifiedCount ?? 0 };
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
