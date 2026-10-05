/** @implements {import('../../interfaces.js').AttemptCounterRepository} */
export class MongoAttemptCounterRepository {
    constructor(model) {
        this.model = model;
    }

    async get(key) {
        const doc = await this.model.findOne({ key }).lean();
        return doc ? toResult(doc) : null;
    }

    /**
     * One atomic upsert via an update pipeline, evaluated against the
     * server's clock ($$NOW) so every app instance agrees on window and lock
     * boundaries. A window that has run out, or a lock that has expired,
     * starts the count over at 1.
     */
    async recordFailure(key, { max, windowSeconds, lockSeconds }) {
        const windowMs = windowSeconds * 1000;
        const lockMs = lockSeconds * 1000;
        const pipeline = [
            {
                $set: {
                    // Start over when the window has run out or a lock has
                    // expired — but never while a lock is still active.
                    _fresh: {
                        $and: [
                            { $not: [{ $gt: [{ $ifNull: ['$lockedUntil', null] }, '$$NOW'] }] },
                            {
                                $or: [
                                    { $lte: [{ $ifNull: ['$windowExpiresAt', null] }, '$$NOW'] },
                                    { $ne: [{ $ifNull: ['$lockedUntil', null] }, null] },
                                ],
                            },
                        ],
                    },
                },
            },
            {
                $set: {
                    count: { $cond: ['$_fresh', 1, { $add: [{ $ifNull: ['$count', 0] }, 1] }] },
                    windowExpiresAt: { $cond: ['$_fresh', { $add: ['$$NOW', windowMs] }, '$windowExpiresAt'] },
                    lockedUntil: { $cond: ['$_fresh', null, { $ifNull: ['$lockedUntil', null] }] },
                },
            },
            {
                $set: {
                    lockedUntil: {
                        $cond: [
                            { $and: [{ $gte: ['$count', max] }, { $eq: ['$lockedUntil', null] }] },
                            { $add: ['$$NOW', lockMs] },
                            '$lockedUntil',
                        ],
                    },
                    expiresAt: { $add: ['$$NOW', Math.max(windowMs, lockMs)] },
                },
            },
            { $unset: '_fresh' },
        ];

        // Mongoose 9 refuses an array update unless asked for explicitly.
        const opts = { upsert: true, returnDocument: 'after', lean: true, updatePipeline: true };
        try {
            return toResult(await this.model.findOneAndUpdate({ key }, pipeline, opts));
        } catch (err) {
            // Two first-ever failures for the same key racing to upsert: one
            // insert wins the unique index, the other retries as an update.
            if (err?.code !== 11000) throw err;
            return toResult(await this.model.findOneAndUpdate({ key }, pipeline, opts));
        }
    }

    async reset(key) {
        await this.model.deleteOne({ key });
    }

    /** No-op — the TTL index on `expiresAt` deletes stale counters natively. */
    async pruneExpired() {
        return { deletedCount: 0 };
    }
}

function toResult(doc) {
    return { count: doc.count, windowExpiresAt: doc.windowExpiresAt, lockedUntil: doc.lockedUntil ?? null };
}
