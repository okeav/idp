import { REQUIRED_STORAGE_METHODS } from '../../src/storage/interfaces.js';

/** A storage object with a no-op for every REQUIRED method (and none of the optional ones), plus `extra` fields. */
export function stubStorage(extra = {}) {
    const storage = { close: async () => {} };
    for (const [repo, methods] of Object.entries(REQUIRED_STORAGE_METHODS)) {
        storage[repo] = Object.fromEntries(methods.map((m) => [m, async () => null]));
    }
    return Object.assign(storage, extra);
}
