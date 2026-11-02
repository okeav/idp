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

    /** A live token by its hash or (email_verification) code hash, WITHOUT consuming it. */
    async findActive(kind, { tokenHash, verificationCode }, userId) {
        const filter = { kind, user: userId, usedAt: null, expiresAt: { $gt: new Date() } };
        if (tokenHash) filter.tokenHash = tokenHash;
        else if (verificationCode) filter.verificationCode = verificationCode;
        else return null;
        return this.model.findOne(filter);
    }

    /** Kills the short, guessable codes of every outstanding row (the unguessable links keep working). */
    async clearCodes(kind, userId) {
        await this.model.updateMany({ kind, user: userId, verificationCode: { $ne: null } }, { $set: { verificationCode: null } });
    }

    /**
     * The single live token of this kind for the user, replaced atomically (password_reset, magic_link):
     * "only the newest link works" must hold even for concurrent requests, which delete-then-create
     * does not guarantee. Backed by a partial unique index on { kind, user }.
     */
    async replaceForUser(kind, userId, input) {
        const update = { $set: { ...input, user: userId, kind, usedAt: null } };
        for (let attempt = 0; ; attempt += 1) {
            try {
                await this.model.findOneAndUpdate({ kind, user: userId }, update, { upsert: true });
                return;
            } catch (err) {
                // Two concurrent upserts can both try to insert; the unique index refuses one — retry it
                // as an update.
                if (err?.code !== 11000 || attempt >= 2) throw err;
            }
        }
    }

    async deleteAllForUser(kind, userId) {
        await this.model.deleteMany({ kind, user: userId });
    }

    async pruneExpired() {
        return { deletedCount: 0 }; // native TTL index handles cleanup
    }
}
