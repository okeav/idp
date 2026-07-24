/**
 * Guarantees a plain string `id` field on documents returned by `.lean()`
 * queries. Hydrated Mongoose documents already expose `.id` via the virtual
 * registered in mongo-id.plugin.js, but `.lean()` results are plain objects
 * with no getters — without this, only `_id` (a BSON ObjectId) would be
 * present, forcing every caller outside this adapter to know Mongo's field
 * name and fall back to it. Repositories route every `.lean()` result
 * through this so `id` is always there and callers never need to reach for
 * `_id`.
 */
export function withId(doc) {
    if (!doc || typeof doc !== 'object') return doc;
    if (doc.id === undefined && doc._id !== undefined) doc.id = String(doc._id);
    return doc;
}

export function withIds(docs) {
    return docs.map(withId);
}
