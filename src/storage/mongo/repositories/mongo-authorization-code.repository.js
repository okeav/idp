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

    async pruneExpired() {
        return { deletedCount: 0 }; // native TTL index handles cleanup
    }
}
