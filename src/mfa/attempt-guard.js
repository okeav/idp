import { IdpError } from '../errors/idp-error.js';
import { auditLog } from '../hooks/index.js';

/**
 * Per-account limit on failed second-factor attempts, shared by every way a
 * code or assertion is checked: TOTP and recovery codes at /mfa/verify,
 * WebAuthn-as-MFA at /webauthn/mfa/verify, and the codes that confirm
 * enrolment and disable MFA. All of them count against one key per user, so
 * an attacker who already has the password can't spread guesses across
 * factors — or across IPs, which is all the per-IP `mfaChallenge` rate limit
 * sees.
 *
 * Counted in `state.attemptCounters` — the storage adapter's
 * `attemptCounterRepository` (shared by every instance) or, for an adapter
 * that doesn't implement one yet, an in-process fallback. A backend error
 * propagates, so the check fails closed.
 */

const LOCKED_ERROR = () => new IdpError({
    code: 'MFA_LOCKED',
    httpStatus: 429,
    message: 'Too many failed verification attempts — try again later.',
});

const keyFor = (userId) => `mfa:${userId}`;

/** Throws MFA_LOCKED (429) while the account's second-factor step is locked — checked BEFORE the submitted code, so the response says nothing about whether it was right. */
export async function assertMfaNotLocked(state, userId) {
    const entry = await state.attemptCounters.get(keyFor(userId));
    if (entry?.lockedUntil && new Date(entry.lockedUntil) > new Date()) throw LOCKED_ERROR();
}

/** Records one failed attempt. When it reaches the limit, emits `MFA_LOCKED` and throws 429 instead of the caller's own error. */
export async function recordMfaFailure(state, userId, { method }) {
    const { maxFailedAttempts, windowSeconds, lockSeconds } = state.config.mfa.lockout;
    const entry = await state.attemptCounters.recordFailure(keyFor(userId), { max: maxFailedAttempts, windowSeconds, lockSeconds });

    if (entry.count >= maxFailedAttempts && entry.lockedUntil) {
        // The counter increments atomically, so exactly one request sees the
        // count land on the limit — that one emits the event, not every
        // straggler in a concurrent burst.
        if (entry.count === maxFailedAttempts) {
            await auditLog(state.logger, state.hooks, 'MFA_LOCKED', {
                userId: String(userId), method, failedAttempts: entry.count, lockedUntil: new Date(entry.lockedUntil).toISOString(),
            });
        }
        throw LOCKED_ERROR();
    }
}

export async function clearMfaFailures(state, userId) {
    await state.attemptCounters.reset(keyFor(userId));
}

/**
 * Runs `verify` (which throws on a wrong code/assertion) under the lockout:
 * refuses up front while locked, counts a failure when `isFailure(err)`, and
 * clears the counter on success. Errors that aren't attempt failures (expired
 * challenge, malformed request) pass through uncounted.
 */
export async function guardMfaAttempt(state, userId, { method, isFailure }, verify) {
    await assertMfaNotLocked(state, userId);
    let result;
    try {
        result = await verify();
    } catch (err) {
        if (isFailure(err)) await recordMfaFailure(state, userId, { method });
        throw err;
    }
    await clearMfaFailures(state, userId);
    return result;
}
