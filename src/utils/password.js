import bcrypt from 'bcrypt';

const DUMMY_HASH = '$2b$12$dummyhashthatisnevergoingtobevalidXXXXXXXXXXXXXXXXXXXX';

export async function hashPassword(password, rounds) {
    return bcrypt.hash(password, rounds);
}

export async function verifyPassword(password, hash) {
    return bcrypt.compare(password, hash);
}

/** Spends roughly the same wall-clock as a real verify, so a login attempt against a nonexistent email doesn't respond faster than one against a real (wrong-password) account. */
export async function compareDummyPassword(password) {
    return bcrypt.compare(password, DUMMY_HASH);
}
