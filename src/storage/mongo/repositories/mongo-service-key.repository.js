import { KEY_STATUS } from '../../../config/constants.js';
import { withIds } from '../normalize.js';

const PUBLISHABLE_STATUSES = [KEY_STATUS.ACTIVE, KEY_STATUS.ROTATING];

/** @implements {import('../../interfaces.js').ServiceKeyRepository} */
export class MongoServiceKeyRepository {
    constructor(model) {
        this.model = model;
    }

    /**
     * Idempotent upsert by kid — re-registering the same (name, publicKey) just bumps lastSeenAt. A
     * REVOKED kid is never brought back: returns null (the unique kid index refuses the insert that the
     * filter would otherwise attempt). Every service re-registers its key on boot, so without this a
     * revoked — i.e. compromised — key was live again at the service's next restart.
     */
    async upsertByKid({ kid, name, publicKey, region }) {
        const now = new Date();
        try {
            return await this.model.findOneAndUpdate(
                { kid, status: { $ne: KEY_STATUS.REVOKED } },
                { $set: { name, publicKey, status: KEY_STATUS.ACTIVE, statusChangedAt: now, region: region || 'global', lastSeenAt: now }, $setOnInsert: { registeredAt: now } },
                { upsert: true, returnDocument: 'after' }
            );
        } catch (err) {
            if (err?.code === 11000) return null;
            throw err;
        }
    }

    /** One key by kid, whatever its status. */
    async findByKid(kid) {
        const doc = await this.model.findOne({ kid }).lean();
        return doc ? withIds([doc])[0] : null;
    }

    /** One publishable key by kid — an indexed read, so verifying a token doesn't scan the collection. */
    async findPublishableByKid(kid) {
        const doc = await this.model.findOne({ kid, status: { $in: PUBLISHABLE_STATUSES } }).lean();
        return doc ? withIds([doc])[0] : null;
    }

    /** Sets a key's status (ROTATING / RETIRED / REVOKED). Returns the updated key, or null. */
    async setStatusByKid(kid, status, { expectedStatus } = {}) {
        // `expectedStatus`: change only from that status (a rotation must not demote a key that was
        // revoked between reading and writing it — REVOKED back to ROTATING would re-enable it).
        const filter = expectedStatus ? { kid, status: expectedStatus } : { kid };
        return this.model.findOneAndUpdate(filter, { $set: { status, statusChangedAt: new Date() } }, { returnDocument: 'after' });
    }

    async listPublishable() {
        return withIds(await this.model.find({ status: { $in: PUBLISHABLE_STATUSES } }).lean());
    }
}
