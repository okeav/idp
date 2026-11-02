/**
 * @typedef {Object} CacheAdapter
 * @property {(key: string) => Promise<any|null>} get
 * @property {(key: string, value: any, ttlSeconds?: number) => Promise<void>} set
 * @property {(key: string) => Promise<void>} del
 * @property {(key: string, ttlSeconds: number) => Promise<void>} expire
 * @property {(key: string) => Promise<any|null>} take - ATOMIC get-and-delete: of two concurrent
 *   callers for one key, exactly one gets the value. The basis of every single-use value (WebAuthn
 *   challenges, SSO state).
 */

/**
 * Base class purely for documentation / instanceof checks — adapters are not
 * required to extend it, only to satisfy the shape above.
 */
export class BaseCacheAdapter {
    async get(_key) { throw new Error('CacheAdapter.get() not implemented'); }
    async set(_key, _value, _ttlSeconds) { throw new Error('CacheAdapter.set() not implemented'); }
    async del(_key) { throw new Error('CacheAdapter.del() not implemented'); }
    async expire(_key, _ttlSeconds) { throw new Error('CacheAdapter.expire() not implemented'); }
    async take(_key) { throw new Error('CacheAdapter.take() not implemented'); }
}
