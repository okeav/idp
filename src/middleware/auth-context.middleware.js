import { getState } from '../config/state.js';
import { verifyAccessToken } from '../signing/token.service.js';
import { isRevoked } from '../cache/index.js';
import { IdpError } from '../errors/idp-error.js';
import { CACHE_KEY_PREFIXES, COOKIE_NAMES } from '../config/constants.js';

function parseBearer(header) {
    if (!header || typeof header !== 'string') return null;
    const match = header.match(/^Bearer\s+(.+)$/i);
    return match ? match[1].trim() : null;
}

/**
 * Authenticates the caller and sets `req.auth = { userId, email, claims, tokenMeta }`.
 * `claims` is whatever opaque object the consumer put on the token at issuance
 * (role/scopes/capabilities/tenant id/anything) — this package never reads it.
 *
 * Accepts either the `access_token` cookie (browser flows, paired with
 * `cookieParser()`) or an `Authorization: Bearer` header (API/service
 * clients). This is broader than the audited source, which only supported
 * cookies plus a BFF-forwarded-context header — see the Phase 3 report for
 * why the forwarded-header mode and the replay-nonce/timestamp check were
 * dropped rather than ported.
 *
 * @param {{ issuer?: string, optional?: boolean }} [opts] - `optional: true`
 *   populates `req.auth` when a valid token is present but calls `next()`
 *   with no error (and `req.auth` left `undefined`) when no token is
 *   presented at all, instead of rejecting. A malformed/expired/revoked
 *   token still rejects even in optional mode — "optional" means "anonymous
 *   is allowed," not "an invalid token is silently ignored." Needed by
 *   endpoints like `/oauth2/authorize` that behave differently for
 *   logged-in vs anonymous callers rather than requiring auth outright.
 */
export function authContextMiddleware(opts = {}) {
    return async function (req, _res, next) {
        try {
            const state = getState();
            const cookieToken = req.cookies?.[COOKIE_NAMES.ACCESS_TOKEN];
            const bearerToken = parseBearer(req.headers.authorization);
            const token = cookieToken || bearerToken;

            if (!token) {
                if (opts.optional) return next();
                throw new IdpError({ code: 'AUTH_REQUIRED', httpStatus: 401, message: 'Authentication is required to access this resource' });
            }

            const payload = await verifyAccessToken(state, token, { issuer: opts.issuer });

            const revokedKey = `${CACHE_KEY_PREFIXES.REVOKED_REFRESH_TOKEN}:${payload.jti}`;
            if (await isRevoked(state.cache, revokedKey)) {
                throw new IdpError({ code: 'TOKEN_REVOKED', httpStatus: 401, message: 'Session has been revoked' });
            }

            req.auth = {
                userId: payload.sub,
                email: payload.email,
                claims: payload.claims || {},
                tokenMeta: { issuedAt: payload.iat, expiresAt: payload.exp, jti: payload.jti },
            };
            next();
        } catch (err) {
            logRejection(req, err);
            next(err);
        }
    };
}

function logRejection(req, err) {
    try {
        getState().logger?.warn?.({ err, path: req.originalUrl }, 'authContextMiddleware rejected request');
    } catch {
        // state not initialized — nothing to log through
    }
}
