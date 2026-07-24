import { withIds } from '../normalize.js';

/** @implements {import('../../interfaces.js').OAuthClientRepository} */
export class MongoOAuthClientRepository {
    constructor(model) {
        this.model = model;
    }

    async create(input) {
        return this.model.create(input);
    }

    async findByClientId(clientId, { includeSecret = false } = {}) {
        const query = this.model.findOne({ clientId });
        return includeSecret ? query.select('+clientSecretHash').exec() : query.exec();
    }

    async findBySlug(slug) {
        return this.model.findOne({ slug });
    }

    async updateByClientId(clientId, patch) {
        return this.model.findOneAndUpdate({ clientId }, { $set: patch }, { returnDocument: 'after' });
    }

    async listMany({ skip = 0, limit = 20 } = {}) {
        return withIds(await this.model.find({}).skip(skip).limit(limit).select('-clientSecretHash').lean());
    }

    async countAll() {
        return this.model.countDocuments();
    }
}
