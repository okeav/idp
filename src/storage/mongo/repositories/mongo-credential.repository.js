import { withIds } from '../normalize.js';

/** @implements {import('../../interfaces.js').CredentialRepository} */
export class MongoCredentialRepository {
    constructor(model) {
        this.model = model;
    }

    async create({ userId, ...rest }) {
        return this.model.create({ user: userId, ...rest });
    }

    async findByCredentialId(credentialId) {
        return this.model.findOne({ credentialId });
    }

    async findByUserId(userId) {
        return withIds(await this.model.find({ user: userId }).lean());
    }

    /**
     * Stores the authenticator's new signature counter — only if it moved forward (an authenticator
     * that doesn't implement a counter reports 0 every time, which is allowed to stay 0). Atomic, so
     * of two concurrent uses of one signed assertion only one gets through. Returns whether it did.
     */
    async updateCounter(credentialId, newCounter) {
        const filter = newCounter > 0
            ? { credentialId, counter: { $lt: newCounter } }
            : { credentialId, counter: 0 };
        const result = await this.model.updateOne(filter, { $set: { counter: newCounter, lastUsedAt: new Date() } });
        return result.modifiedCount === 1;
    }

    /** Scoped to the owner. Returns whether a credential was deleted. */
    async deleteByCredentialId(credentialId, userId) {
        const result = await this.model.deleteOne({ credentialId, user: userId });
        return result.deletedCount === 1;
    }

    async countForUser(userId) {
        return this.model.countDocuments({ user: userId });
    }
}
