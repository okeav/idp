/** @implements {import('../../interfaces.js').ConsentRepository} */
export class MongoConsentRepository {
    constructor(model) {
        this.model = model;
    }

    async upsert(userId, clientId, scopes) {
        return this.model.findOneAndUpdate(
            { userId, clientId },
            { $set: { scopes, grantedAt: new Date(), isRevoked: false, revokedAt: null } },
            { upsert: true, returnDocument: 'after' }
        );
    }

    async find(userId, clientId) {
        return this.model.findOne({ userId, clientId, isRevoked: false });
    }

    async listForUser(userId) {
        return this.model.find({
            userId,
            isRevoked: false,
            $or: [{ revokedAt: null }, { revokedAt: { $exists: false } }],
        });
    }

    async revoke(userId, clientId) {
        await this.model.findOneAndUpdate({ userId, clientId }, { $set: { isRevoked: true, revokedAt: new Date() } });
    }
}
