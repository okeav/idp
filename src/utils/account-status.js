import { IDENTITY_STATUS } from '../config/constants.js';

/**
 * The failed-password lockout is a property of PASSWORD login (`lockUntil`), not an account status.
 * As a status it locked the owner out of every other method too — magic link, passkey, SSO, MFA,
 * refresh, OAuth2 — so five anonymous wrong passwords were a denial of service against any account,
 * and a passwordless account (which never makes a password login to lift it) stayed locked for good.
 *
 * Rows locked before 0.4.0 carry `status: LOCKED` together with a `lockUntil`: that is the automatic
 * lockout, and counts as ACTIVE here. A LOCKED status with no `lockUntil` is an administrative lock
 * and still blocks every method.
 */
export function effectiveStatus(user) {
    if (user?.status === IDENTITY_STATUS.LOCKED && user.lockUntil) return IDENTITY_STATUS.ACTIVE;
    return user?.status;
}

/** Whether the account may sign in / keep its sessions (any method). */
export function isActiveAccount(user) {
    return Boolean(user) && effectiveStatus(user) === IDENTITY_STATUS.ACTIVE;
}

/** Whether password login is currently locked by failed attempts. */
export function isPasswordLocked(user) {
    return Boolean(user?.lockUntil) && new Date(user.lockUntil) > new Date();
}
