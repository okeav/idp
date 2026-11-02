import { KEY_STATUS } from '../../../config/constants.js';
import { withIds } from '../normalize.js';

const PUBLISHABLE_STATUSES = [KEY_STATUS.ACTIVE, KEY_STATUS.ROTATING];

/** @implements {import('../../interfaces.js').ServiceKeyRepository} */
export class MongoServiceKeyRepository {
    constructor(model) {
        this.model = model;
    }

    /** Idempotent upsert by kid — re-registering the same (name, publicKey) just bumps lastSeenAt. */
    async upsertByKid({ kid, name, publicKey, region }) {
        const now = new Date();
        return this.model.findOneAndUpdate(
            { kid },
            { $set: { name, publicKey, status: KEY_STATUS.ACTIVE, region: region || 'global', lastSeenAt: now }, $setOnInsert: { registeredAt: now } },
            { upsert: true, returnDocument: 'after' }
        );
    }

    /** One publishable key by kid — an indexed read, so verifying a token doesn't scan the collection. */
    async findPublishableByKid(kid) {
        const doc = await this.model.findOne({ kid, status: { $in: PUBLISHABLE_STATUSES } }).lean();
        return doc ? withIds([doc])[0] : null;
    }

    /** Sets a key's status (ROTATING / RETIRED / REVOKED). Returns the updated key, or null. */
    async setStatusByKid(kid, status) {
        return this.model.findOneAndUpdate({ kid }, { $set: { status } }, { returnDocument: 'after' });
    }

    async listPublishable() {
        return withIds(await this.model.find({ status: { $in: PUBLISHABLE_STATUSES } }).lean());
    }
}
