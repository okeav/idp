import crypto from 'crypto';
import bcrypt from 'bcrypt';

const SALT_ROUNDS = 12;

export function generateClientId() {
    return crypto.randomBytes(16).toString('hex');
}

export function generateClientSecret() {
    return crypto.randomBytes(32).toString('hex');
}

export async function hashClientSecret(clientSecret) {
    return bcrypt.hash(clientSecret, SALT_ROUNDS);
}

export async function verifyClientSecret(clientSecret, hash) {
    return bcrypt.compare(clientSecret, hash);
}
