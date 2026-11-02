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
        try {
            // Times from the DATABASE clock ($$NOW), not this instance's: registeredAt orders concurrent
            // first registrations of one name (the earliest keeps it), which only works if it reflects
            // the order the inserts actually happened in.
            return await this.model.findOneAndUpdate(
                { kid, status: { $ne: KEY_STATUS.REVOKED } },
                [{ $set: {
                    kid, name, publicKey, status: KEY_STATUS.ACTIVE, region: region || 'global',
                    statusChangedAt: '$$NOW', lastSeenAt: '$$NOW', registeredAt: { $ifNull: ['$registeredAt', '$$NOW'] },
                } }],
                { upsert: true, returnDocument: 'after', setDefaultsOnInsert: false, updatePipeline: true }
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
