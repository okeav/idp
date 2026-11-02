/**
 * Per-key limit on attempts at a secret (a code, a password, an assertion),
 * counted in `state.attemptCounters` so it holds across instances.
 *
 * The attempt is counted BEFORE the secret is checked, not after a failure.
 * Counting after is a check-then-act race: N concurrent requests all read
 * "not locked", all get their guess checked, and only then are N failures
 * recorded — a burst gets as many guesses as it has requests. Counting first
 * makes the counter's atomic increment the gate: each concurrent request sees
 * a distinct count, and only the first `maxFailedAttempts` within a window get
 * checked. A success resets the counter, so the reservation it made costs
 * nothing. (An attempt that errors for another reason — an expired challenge,
 * say — keeps its reservation: when in doubt, it counts.)
 *
 * The failed attempt that uses up the budget answers with `lockedError` (not
 * its own error) and runs `onLocked` once; every later attempt is refused with
 * the identical `lockedError` before its secret is looked at, whatever it was.
 *
 * A counter backend error propagates, so this fails closed.
 *
 * @param {object} state
 * @param {string} key
 * @param {{ maxFailedAttempts: number, windowSeconds: number, lockSeconds: number }} limits
 * @param {{ lockedError: () => Error, onLocked?: (entry) => Promise<void>, isFailure?: (err) => boolean }} opts
 *   `isFailure` decides whether an error from `verify` was a wrong guess (default: any error).
 * @param {() => Promise<T>} verify - throws on a wrong secret.
 * @returns {Promise<T>}
 * @template T
 */
export async function withAttemptBudget(state, key, limits, { lockedError, onLocked, isFailure = () => true }, verify) {
    const { maxFailedAttempts: max, windowSeconds, lockSeconds } = limits;
    const entry = await state.attemptCounters.recordFailure(key, { max, windowSeconds, lockSeconds });
    if (entry.count > max) throw lockedError();

    let result;
    try {
        result = await verify();
    } catch (err) {
        if (entry.count === max && isFailure(err)) {
            if (onLocked) await onLocked(entry);
            throw lockedError();
        }
        throw err;
    }
    await state.attemptCounters.reset(key);
    return result;
}
