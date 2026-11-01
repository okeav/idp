import bcrypt from 'bcrypt';

const DUMMY_HASH = '$2b$12$dummyhashthatisnevergoingtobevalidXXXXXXXXXXXXXXXXXXXX';

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
    return bcrypt.compare(password, DUMMY_HASH);
}
