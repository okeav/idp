/**
 * Single-use bookkeeping for second factors. Each prefers the storage adapter's atomic method and
 * falls back to a read-then-write for adapters that don't have it yet (initIdentityProvider warns
 * about those at startup — the fallback is correct for sequential requests but racy under
 * concurrency).
 */

/** Claims TOTP time step `step` for the user; false if it (or a later one) was already used. */
export async function claimTotpStep(state, userId, step) {
    const repo = state.storage.userRepository;
    if (typeof repo.claimTotpStep === 'function') return repo.claimTotpStep(userId, step);
    const user = await repo.findById(userId, { select: '+mfaLastTotpStep' });
    if (user?.mfaLastTotpStep != null && user.mfaLastTotpStep >= step) return false;
    await repo.updateById(userId, { mfaLastTotpStep: step });
    return true;
}

/** Spends the unused recovery code whose hash is `codeHash`; false if there is none. */
export async function consumeRecoveryCode(state, user, codeHash) {
    const repo = state.storage.userRepository;
    if (typeof repo.consumeRecoveryCode === 'function') return repo.consumeRecoveryCode(user.id, codeHash);
    const idx = (user.mfaRecoveryCodes || []).findIndex((rc) => !rc.usedAt && rc.codeHash === codeHash);
    if (idx < 0) return false;
    await repo.updateById(user.id, { [`mfaRecoveryCodes.${idx}.usedAt`]: new Date() });
    return true;
}

/**
 * Lets an MFA challenge token complete exactly one login. Claimed in the shared attempt-counter
 * store (atomic, visible to every instance) under the token's `jti`, for as long as the token lives.
 * Returns false if the token was already used.
 */
export async function claimMfaChallenge(state, challengeClaims) {
    const ttl = Math.max(1, (challengeClaims.exp ?? 0) - Math.floor(Date.now() / 1000) + 60);
    const entry = await state.attemptCounters.recordFailure(`mfa-challenge-used:${challengeClaims.jti}`, { max: 1, windowSeconds: ttl, lockSeconds: ttl });
    return entry.count === 1;
}
