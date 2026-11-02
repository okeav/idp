import { IdpError } from '../errors/idp-error.js';
import { auditLog } from '../hooks/index.js';
import { withAttemptBudget } from '../security/attempt-budget.js';

/**
 * Per-account limit on failed second-factor attempts, shared by every way a
 * code or assertion is checked: TOTP and recovery codes at /mfa/verify,
 * WebAuthn-as-MFA at /webauthn/mfa/verify, and the codes that confirm
 * enrolment, disable MFA, and regenerate recovery codes. All of them count
 * against one key per user, so an attacker who already has the password can't
 * spread guesses across factors — or across IPs, which is all the per-IP
 * `mfaChallenge` rate limit sees.
 *
 * Counted in `state.attemptCounters` — the storage adapter's
 * `attemptCounterRepository` (shared by every instance) or, for an adapter
 * that doesn't implement one yet, an in-process fallback. Attempts are counted
 * before the code is checked (see security/attempt-budget.js), so a concurrent
 * burst gets no more guesses than the budget. A backend error propagates, so
 * the check fails closed.
 */

const LOCKED_ERROR = () => new IdpError({
    code: 'MFA_LOCKED',
    httpStatus: 429,
    message: 'Too many failed verification attempts — try again later.',
});

const keyFor = (userId) => `mfa:${userId}`;

/**
 * Runs `verify` (which throws on a wrong code/assertion) under the lockout.
 * `isFailure(err)` says whether an error was a wrong guess; the failed guess
 * that uses up the budget is answered with MFA_LOCKED and emits one
 * `MFA_LOCKED` audit event.
 */
export async function guardMfaAttempt(state, userId, { method, isFailure }, verify) {
    return withAttemptBudget(state, keyFor(userId), state.config.mfa.lockout, {
        lockedError: LOCKED_ERROR,
        isFailure,
        onLocked: (entry) => auditLog(state.logger, state.hooks, 'MFA_LOCKED', {
            userId: String(userId), method, failedAttempts: entry.count, lockedUntil: new Date(entry.lockedUntil).toISOString(),
        }),
    }, verify);
}

export async function clearMfaFailures(state, userId) {
    await state.attemptCounters.reset(keyFor(userId));
}
