/**
 * Adds a virtual `id` (string form of `_id`) and strips `__v` from the JSON
 * representation of every document — a small convenience so callers don't
 * need to know they're looking at a Mongo document.
 */
export function mongoIdPlugin(schema) {
    if (!schema.virtuals?.id) {
        schema.virtual('id').get(function () {
            return this._id?.toString();
        });
    }
    schema.set('toJSON', {
        virtuals: true,
        transform: (_doc, ret) => {
            delete ret.__v;
            return ret;
        },
    });
}
