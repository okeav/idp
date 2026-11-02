import { getState } from '../config/state.js';
import { IdpError } from '../errors/idp-error.js';

/**
 * Step-up gate for changes that would let a stolen session outlive itself — adding a passkey,
 * enrolling MFA, deleting a passkey or the account. Mount after `authContextMiddleware()`.
 *
 * Passes only when the user actually authenticated (password + MFA, magic link, SSO, passkey —
 * not a token refresh) within `maxAgeSeconds` (default `config.session.recentAuthMaxAgeSeconds`,
 * 15 minutes). Otherwise answers 401 `REAUTHENTICATION_REQUIRED`: the client sends the user
 * through a login again and retries with the new token. A token without `auth_time` (one minted
 * through the public `issueAccessToken()` export, or refreshed from a pre-0.4.0 session) never
 * counts as recent.
 *
 * @param {{ maxAgeSeconds?: number }} [opts]
 */
export function requireRecentAuth(opts = {}) {
    if (opts.maxAgeSeconds !== undefined && !(Number.isInteger(opts.maxAgeSeconds) && opts.maxAgeSeconds > 0)) {
        throw new Error('requireRecentAuth: maxAgeSeconds must be a positive integer');
    }
    return function (req, _res, next) {
        const maxAge = opts.maxAgeSeconds ?? getState().config.session.recentAuthMaxAgeSeconds;
        const authTime = req.auth?.tokenMeta?.authTime;
        const now = Math.floor(Date.now() / 1000);
        if (!Number.isInteger(authTime) || authTime > now + 60 || now - authTime > maxAge) {
            return next(new IdpError({ code: 'REAUTHENTICATION_REQUIRED', httpStatus: 401, message: 'Please sign in again to continue' }));
        }
        next();
    };
}
