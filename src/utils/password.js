import crypto from 'crypto';
import bcrypt from 'bcrypt';

// A real hash at the configured cost (set by prepareDummyHash at init). A fixed cost-12 constant made
// "no such account" slower or faster than a real compare whenever bcryptRounds wasn't 12 — a timing
// oracle for which emails exist, and which accounts have no password.
let dummyHash = null;

/** The cost of the current dummy hash (tests). */
export function dummyHashRounds() {
    return dummyHash ? bcrypt.getRounds(dummyHash) : null;
}

/** Called by initIdentityProvider with `security.bcryptRounds`. */
export async function prepareDummyHash(rounds) {
    dummyHash = await bcrypt.hash(crypto.randomBytes(16).toString('hex'), rounds);
}

export async function hashPassword(password, rounds) {
    return bcrypt.hash(password, rounds);
}

/**
 * False — never a throw — for an account with no password (SSO-only, magic-link-only, or one whose
 * pre-verification password was discarded): bcrypt throws on a missing hash, which surfaced as a 500
 * that told an attacker exactly which accounts are passwordless. The dummy compare keeps the timing.
 */
export async function verifyPassword(password, hash) {
    if (typeof hash !== 'string' || hash.length === 0) {
        await compareDummyPassword(password);
        return false;
    }
    return bcrypt.compare(password, hash);
}

/** Spends roughly the same wall-clock as a real verify, so a login attempt against a nonexistent email doesn't respond faster than one against a real (wrong-password) account. */
export async function compareDummyPassword(password) {
    if (!dummyHash) await prepareDummyHash(12);
    return bcrypt.compare(password, dummyHash);
}
