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

    async listPublishable() {
        return withIds(await this.model.find({ status: { $in: PUBLISHABLE_STATUSES } }).lean());
    }
}
