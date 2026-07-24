/** @implements {import('../../interfaces.js').VerificationTokenRepository} */
export class MongoVerificationTokenRepository {
    constructor(model) {
        this.model = model;
    }

    async create(kind, input) {
        await this.model.create({ kind, ...input });
    }

    /** Atomic consume-by-hash. `userId`, when given, scopes the consume to the claimed identity (password reset). */
    async consumeByHash(kind, hash, userId) {
        const filter = { kind, tokenHash: hash, usedAt: null, expiresAt: { $gt: new Date() } };
        if (userId) filter.user = userId;
        if (kind === 'email_verification' || kind === 'magic_link') {
            // Single-use-by-deletion rather than a usedAt flag — matches the
            // audited email-verification behavior; a clicked magic link should
            // behave the same way (one link, one login, gone afterward).
            return this.model.findOneAndDelete(filter);
        }
        return this.model.findOneAndUpdate(filter, { usedAt: new Date() }, { returnDocument: 'after' });
    }

    async consumeByCode(kind, code, userId) {
        return this.model.findOneAndDelete({ kind, verificationCode: code, user: userId, expiresAt: { $gt: new Date() } });
    }

    async deleteAllForUser(kind, userId) {
        await this.model.deleteMany({ kind, user: userId });
    }

    async pruneExpired() {
        return { deletedCount: 0 }; // native TTL index handles cleanup
    }
}
