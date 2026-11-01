/**
 * Per-key limit on attempts at a secret (a code, a password, an assertion),
 * counted in `state.attemptCounters` so it holds across instances.
 *
 * The attempt is counted BEFORE the secret is checked, not after a failure.
 * Counting after is a check-then-act race: N concurrent requests all read
 * "not locked", all get their guess checked, and only then are N failures
 * recorded — a burst gets as many guesses as it has requests. Counting first
 * makes the counter's atomic increment the gate: each concurrent request sees
 * a distinct count, and only the first `max` within a window get checked.
 * A success resets the counter, so the reservation it made costs nothing.
 *
 * A counter backend error propagates, so this fails closed.
 *
 * @param {object} state
 * @param {string} key
 * @param {{ maxFailedAttempts: number, windowSeconds: number, lockSeconds: number }} limits
 * @param {{ lockedError: () => Error, onLocked?: (entry) => Promise<void> }} hooks
 *   `lockedError` is thrown for every attempt refused while locked (identical, whatever was
 *   submitted). `onLocked` runs once, on the failed attempt that used up the budget.
 * @param {() => Promise<T>} verify - throws on a wrong secret.
 * @returns {Promise<T>}
 * @template T
 */
export async function withAttemptBudget(state, key, limits, { lockedError, onLocked }, verify) {
    const { maxFailedAttempts: max, windowSeconds, lockSeconds } = limits;
    const entry = await state.attemptCounters.recordFailure(key, { max, windowSeconds, lockSeconds });
    if (entry.count > max) throw lockedError();

    let result;
    try {
        result = await verify();
    } catch (err) {
        // The attempt that used up the budget is the one that reports it.
        if (entry.count === max && onLocked) await onLocked(entry);
        throw err;
    }
    await state.attemptCounters.reset(key);
    return result;
}
