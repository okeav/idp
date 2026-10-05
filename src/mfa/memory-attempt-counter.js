/**
 * In-process `AttemptCounterRepository` — the fallback used when a storage
 * adapter doesn't provide `attemptCounterRepository` yet. Same caveat as
 * MemoryRateLimiter: correct for a single instance, but each instance of a
 * horizontally-scaled deployment keeps its own count. initIdentityProvider()
 * logs a warning when it falls back to this.
 *
 * @implements {import('../storage/interfaces.js').AttemptCounterRepository}
 */
export class MemoryAttemptCounterRepository {
    constructor({ now = () => Date.now() } = {}) {
        this._now = now;
        this._store = new Map(); // key -> { count, windowExpiresAt, lockedUntil }
    }

    async get(key) {
        const entry = this._store.get(key);
        return entry ? toResult(entry) : null;
    }

    async recordFailure(key, { max, windowSeconds, lockSeconds }) {
        const now = this._now();
        const prev = this._store.get(key);
        // Start over when the window has run out or a lock has expired — but
        // never while a lock is still active.
        const lockActive = prev?.lockedUntil != null && prev.lockedUntil > now;
        const fresh = !prev || (!lockActive && (prev.windowExpiresAt <= now || prev.lockedUntil !== null));
        const entry = fresh
            ? { count: 1, windowExpiresAt: now + windowSeconds * 1000, lockedUntil: null }
            : { ...prev, count: prev.count + 1 };
        if (entry.count >= max && entry.lockedUntil === null) entry.lockedUntil = now + lockSeconds * 1000;
        this._store.set(key, entry);
        return toResult(entry);
    }

    async reset(key) {
        this._store.delete(key);
    }

    async pruneExpired() {
        const now = this._now();
        let deletedCount = 0;
        for (const [key, e] of this._store) {
            if (e.windowExpiresAt <= now && (e.lockedUntil === null || e.lockedUntil <= now)) {
                this._store.delete(key);
                deletedCount += 1;
            }
        }
        return { deletedCount };
    }
}

function toResult(e) {
    return { count: e.count, windowExpiresAt: new Date(e.windowExpiresAt), lockedUntil: e.lockedUntil === null ? null : new Date(e.lockedUntil) };
}
