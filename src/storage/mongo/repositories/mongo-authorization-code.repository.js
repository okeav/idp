/** @implements {import('../../interfaces.js').AuthorizationCodeRepository} */
export class MongoAuthorizationCodeRepository {
    constructor(model) {
        this.model = model;
    }

    async create(input) {
        await this.model.create(input);
    }

    /** Atomic find+mark-used — the OAuth2 spec requires a code be exchangeable exactly once. */
    async consumeByCodeHash(hash) {
        return this.model.findOneAndUpdate(
            { code: hash, used: false, expiresAt: { $gt: new Date() } },
            { used: true, usedAt: new Date() },
            { returnDocument: 'after' }
        );
    }

    /** A code that was already redeemed (for reuse detection). Null for an unknown or still-unused code. */
    async findUsedByCodeHash(hash) {
        return this.model.findOne({ code: hash, used: true });
    }

    /** Flags a redeemed code as presented again (reuse) — read back by the redemption still in flight. */
    async markReused(hash) {
        await this.model.updateOne({ code: hash, used: true }, { $set: { reuseDetectedAt: new Date() } });
    }

    async pruneExpired() {
        return { deletedCount: 0 }; // native TTL index handles cleanup
    }
}
