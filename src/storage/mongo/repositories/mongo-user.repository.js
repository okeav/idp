import { withIds } from '../normalize.js';

/** @implements {import('../../interfaces.js').UserRepository} */
export class MongoUserRepository {
    /**
     * @param {import('mongoose').Model} model
     * @param {{ hashEmail: (email: string) => string, normalizeEmail: (email: string) => string }} deps
     */
    constructor(model, { hashEmail, normalizeEmail }) {
        this.model = model;
        this._hashEmail = hashEmail;
        this._normalizeEmail = normalizeEmail;
    }

    async create(data) {
        const doc = await this.model.create(data);
        return doc;
    }

    async findById(id, opts = {}) {
        let query = this.model.findById(id);
        if (opts.select) query = query.select(opts.select);
        return query.exec();
    }

    async findByEmail(email, opts = {}) {
        if (!email) return null;
        const normalized = this._normalizeEmail(email);
        let query = this.model.findOne({
            $or: [{ emailHash: this._hashEmail(normalized) }, { email: normalized }],
        });
        if (opts.select) query = query.select(opts.select);
        return query.exec();
    }

    async findByExternalProvider(provider, providerId) {
        return this.model.findOne({ externalProviders: { $elemMatch: { provider, providerId } } });
    }

    async updateById(id, patch, opts = {}) {
        return this.model.findByIdAndUpdate(id, { $set: patch }, { returnDocument: 'after', ...opts });
    }

    async incrementFailedLoginAttempts(id) {
        return this.model.findByIdAndUpdate(id, { $inc: { failedLoginAttempts: 1 } }, { returnDocument: 'after' });
    }

    async linkExternalProvider(id, link) {
        return this.model.findByIdAndUpdate(id, { $push: { externalProviders: link } }, { returnDocument: 'after' });
    }

    async deleteById(id) {
        await this.model.deleteOne({ _id: id });
    }

    async countAll() {
        return this.model.countDocuments();
    }

    async findMany({ skip = 0, limit = 20 } = {}) {
        return withIds(await this.model.find({}).skip(skip).limit(limit).select('-passwordHash -mfaSecret').lean());
    }
}
