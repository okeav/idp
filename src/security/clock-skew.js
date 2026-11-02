/**
 * Clock skew between this app server and the database.
 *
 * Revocation ordering doesn't use clocks (it uses counters and the database's own clock), but expiry
 * does: token `exp`, code and link lifetimes and lockout windows are compared against the clock of the
 * server checking them. Servers whose clocks disagree would let something live longer — or die sooner —
 * than configured. So, as Kerberos does, the skew is bounded: each server measures its clock against
 * the database's at startup (refusing to start past `clock.maxSkewSeconds`) and again every
 * `clock.checkIntervalSeconds` (logging an error past it). Every server measured against the same
 * clock is then within 2 × maxSkewSeconds of every other.
 */

/**
 * This server's clock minus the database's, in ms (the database's reading is taken as the midpoint
 * of the round trip). Null when the storage adapter can't tell the time (`storage.databaseTime`).
 */
export async function measureClockSkew(storage) {
    if (typeof storage?.databaseTime !== 'function') return null;
    const sent = Date.now();
    const { time } = await storage.databaseTime();
    const received = Date.now();
    const dbTime = new Date(time).getTime();
    if (!Number.isFinite(dbTime)) throw new Error('storage.databaseTime() did not return a valid time');
    return Math.round((sent + received) / 2 - dbTime);
}

/** `{ skewMs, ok, level }` for the current skew — `level`: 'ok', 'warn' (past warnSkewSeconds) or 'error' (past maxSkewSeconds). */
export async function checkSkew(storage, clockConfig) {
    const skewMs = await measureClockSkew(storage);
    if (skewMs === null) return { skewMs: null, ok: true, level: 'unknown' };
    const abs = Math.abs(skewMs);
    const level = abs > clockConfig.maxSkewSeconds * 1000 ? 'error' : abs > clockConfig.warnSkewSeconds * 1000 ? 'warn' : 'ok';
    return { skewMs, ok: level !== 'error', level };
}

const message = (skewMs, clock) => `This server's clock is ${(Math.abs(skewMs) / 1000).toFixed(1)}s ${skewMs > 0 ? 'ahead of' : 'behind'} the database's `
    + `(limit ${clock.maxSkewSeconds}s) — token and code lifetimes would be wrong. Sync the clock (NTP).`;

/**
 * Startup: refuses (throws) past maxSkewSeconds, warns past warnSkewSeconds, then re-checks every
 * checkIntervalSeconds. Resolves a `stop()` for the periodic check.
 */
export async function startClockSkewGuard(storage, clock, logger) {
    if (typeof storage?.databaseTime !== 'function') {
        logger?.warn?.({}, '@okeav/idp-core: the storage adapter has no databaseTime() — clock skew between servers is not checked. Upgrade the adapter.');
        return () => {};
    }
    const first = await checkSkew(storage, clock);
    if (first.level === 'error') throw new Error(message(first.skewMs, clock));
    if (first.level === 'warn') logger?.warn?.({ skewMs: first.skewMs }, message(first.skewMs, clock));

    const timer = setInterval(async () => {
        try {
            const { skewMs, level } = await checkSkew(storage, clock);
            if (level === 'error') logger?.error?.({ skewMs }, message(skewMs, clock));
            else if (level === 'warn') logger?.warn?.({ skewMs }, message(skewMs, clock));
        } catch (err) {
            logger?.warn?.({ err: { name: err?.name, message: err?.message } }, 'Clock skew check failed');
        }
    }, clock.checkIntervalSeconds * 1000);
    timer.unref?.();
    return () => clearInterval(timer);
}
