import { BaseCacheAdapter } from './cache-adapter.js';

/**
 * Zero-config default cache adapter. Single-process, in-memory only — state
 * is lost on restart and NOT shared across instances.
 *
 * This is fine for local development or a single-instance deployment. Any
 * horizontally-scaled deployment (more than one process/pod) MUST configure
 * the Redis adapter instead, or two invariants silently break:
 *   1. Revocation checks (logout, refresh rotation) only apply on the
 *      instance that handled the revoking request.
 *   2. SSO CSRF-state and the replay-nonce cache aren't shared, so a
 *      callback landing on a different instance than the one that issued
 *      the redirect will spuriously fail.
 */
export class MemoryCacheAdapter extends BaseCacheAdapter {
    constructor({ sweepIntervalMs = 60_000 } = {}) {
        super();
        this._store = new Map(); // key -> { value, expiresAt: number|null }
        this._sweepInterval = setInterval(() => this._sweep(), sweepIntervalMs);
        this._sweepInterval.unref?.();
    }

    async get(key) {
        const entry = this._store.get(key);
        if (!entry) return null;
        if (entry.expiresAt !== null && entry.expiresAt <= Date.now()) {
            this._store.delete(key);
            return null;
        }
        return entry.value;
    }

    async set(key, value, ttlSeconds) {
        const expiresAt = ttlSeconds ? Date.now() + ttlSeconds * 1000 : null;
        this._store.set(key, { value, expiresAt });
    }

    async del(key) {
        this._store.delete(key);
    }

    async expire(key, ttlSeconds) {
        const entry = this._store.get(key);
        if (!entry) return;
        entry.expiresAt = Date.now() + ttlSeconds * 1000;
    }

    _sweep() {
        const now = Date.now();
        for (const [key, entry] of this._store) {
            if (entry.expiresAt !== null && entry.expiresAt <= now) this._store.delete(key);
        }
    }

    /** Stops the background sweep timer — call on graceful shutdown in tests/short-lived processes. */
    close() {
        clearInterval(this._sweepInterval);
    }
}
