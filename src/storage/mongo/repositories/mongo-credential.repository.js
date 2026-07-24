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

    async updateCounter(credentialId, newCounter) {
        await this.model.findOneAndUpdate({ credentialId }, { $set: { counter: newCounter, lastUsedAt: new Date() } });
    }

    async deleteByCredentialId(credentialId, userId) {
        await this.model.deleteOne({ credentialId, user: userId });
    }

    async countForUser(userId) {
        return this.model.countDocuments({ user: userId });
    }
}
