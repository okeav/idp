import { BaseRateLimiter } from './rate-limiter.js';

/**
 * Zero-config default. Fixed-window counter, single-process only — same
 * caveat as MemoryCacheAdapter: fine for local dev or a genuinely
 * single-instance deployment, wrong for anything horizontally scaled (each
 * instance would enforce its own independent limit).
 */
export class MemoryRateLimiter extends BaseRateLimiter {
    /**
     * @param {{ sweepIntervalMs?: number, maxKeys?: number }} [opts] - `maxKeys` bounds memory. When full
     *   (after sweeping expired windows), a NEW key is refused with an error — which the fail-closed call
     *   sites turn into 503 — rather than evicting another key: eviction would let an attacker flush
     *   their own counter by flooding distinct keys.
     */
    constructor({ sweepIntervalMs = 60_000, maxKeys = 500_000 } = {}) {
        super();
        this._maxKeys = maxKeys;
        this._store = new Map(); // key -> { count, resetAt }
        this._sweepInterval = setInterval(() => this._sweep(), sweepIntervalMs);
        this._sweepInterval.unref?.();
    }

    async check(key) {
        const entry = this._store.get(key);
        if (!entry || entry.resetAt <= Date.now()) return { allowed: true, remaining: Infinity, resetAt: 0 };
        return { allowed: true, remaining: Infinity, resetAt: entry.resetAt }; // max unknown without opts — see increment()
    }

    async increment(key, { max, windowSeconds }) {
        const now = Date.now();
        let entry = this._store.get(key);
        if (!entry || entry.resetAt <= now) {
            if (!entry && this._store.size >= this._maxKeys) {
                this._sweep();
                if (this._store.size >= this._maxKeys) throw new Error('MemoryRateLimiter is full (maxKeys) — refusing to track a new key');
            }
            entry = { count: 0, resetAt: now + windowSeconds * 1000 };
        }
        entry.count += 1;
        this._store.set(key, entry);
        return { allowed: entry.count <= max, remaining: Math.max(0, max - entry.count), resetAt: entry.resetAt };
    }

    async reset(key) {
        this._store.delete(key);
    }

    _sweep() {
        const now = Date.now();
        for (const [key, entry] of this._store) {
            if (entry.resetAt <= now) this._store.delete(key);
        }
    }

    close() {
        clearInterval(this._sweepInterval);
    }
}
