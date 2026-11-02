import { getState } from '../config/state.js';
import { verifyAccessToken, classifyAccessToken } from '../signing/token.service.js';
import { isRevoked } from '../cache/index.js';
import { IdpError } from '../errors/idp-error.js';
import { CACHE_KEY_PREFIXES, COOKIE_NAMES, ACCESS_TOKEN_KINDS } from '../config/constants.js';
import { assertTrustedOrigin } from './csrf.js';

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
 * @param {Array<'first-party'|'oauth2-user'|'oauth2-client'>} [opts.accept] - which kinds of
 *   access token are credentials here. Default `['first-party']`: a token this IdP issued to a
 *   third-party OAuth2 client is never accepted on the IdP's own routes. A resource server that
 *   serves OAuth2 clients opts in with `accept: ['oauth2-user']` (and/or `'oauth2-client'` for
 *   client_credentials machine tokens) — then check `req.auth.scopes`.
 * @param {string|string[]} [opts.audience] - the `aud` a first-party token must carry (default: the issuer).
 */
export function authContextMiddleware(opts = {}) {
    const accept = opts.accept ?? [ACCESS_TOKEN_KINDS.FIRST_PARTY];
    if (!Array.isArray(accept) || accept.length === 0 || accept.some((k) => !Object.values(ACCESS_TOKEN_KINDS).includes(k))) {
        throw new Error(`authContextMiddleware: opts.accept must be a non-empty array of ${Object.values(ACCESS_TOKEN_KINDS).join(', ')}`);
    }
    return async function (req, _res, next) {
        try {
            const state = getState();
            const rawCookie = req.cookies?.[COOKIE_NAMES.ACCESS_TOKEN];
            const cookieToken = typeof rawCookie === 'string' ? rawCookie : undefined;
            const bearerToken = parseBearer(req.headers.authorization);
            const token = cookieToken || bearerToken;

            if (!token) {
                if (opts.optional) return next();
                throw new IdpError({ code: 'AUTH_REQUIRED', httpStatus: 401, message: 'Authentication is required to access this resource' });
            }

            // The cookie is attached by the browser whoever builds the request — so it must come from a trusted origin.
            if (token === cookieToken) assertTrustedOrigin(state, req);
            const payload = await verifyAccessToken(state, token, { issuer: opts.issuer, audience: opts.audience, accept });
            await assertSessionLive(state, payload);

            const kind = classifyAccessToken(payload);
            const isClientToken = kind === ACCESS_TOKEN_KINDS.OAUTH2_CLIENT;
            req.auth = {
                // A client_credentials token has no user — never surface the client id as a userId.
                userId: isClientToken ? undefined : payload.sub,
                email: payload.email,
                claims: payload.claims || {},
                tokenKind: kind,
                ...(payload.client_id ? { clientId: payload.client_id, scopes: String(payload.scope || '').split(' ').filter(Boolean) } : {}),
                tokenMeta: { issuedAt: payload.iat, expiresAt: payload.exp, jti: payload.jti, authTime: payload.auth_time ?? null },
            };
            next();
        } catch (err) {
            logRejection(req, err);
            next(err);
        }
    };
}

const REVOKED = () => new IdpError({ code: 'TOKEN_REVOKED', httpStatus: 401, message: 'Session has been revoked' });

/**
 * Revocation check. The per-process cache is only ever a fast path: a cache
 * "revoked" short-circuits, but a cache "not revoked" (or a miss) never
 * skips the storage check while `session.verifyOnEachRequest` is on — the
 * session row is the authority, and the only thing every instance shares.
 *
 * Tokens carrying `sessionless: true` (client_credentials grants and the
 * public `issueAccessToken()` export — neither has a session row) skip the
 * storage check; they were never tied to a session to revoke.
 */
async function assertSessionLive(state, payload) {
    const verifyInStorage = state.config.session?.verifyOnEachRequest === true
        && payload.sessionless !== true
        && typeof state.storage.sessionRepository?.findByJti === 'function';
    const revokedKey = `${CACHE_KEY_PREFIXES.REVOKED_REFRESH_TOKEN}:${payload.jti}`;

    if (!verifyInStorage) {
        // Cache-only mode (opted out, or an adapter without findByJti): the
        // cache is all there is, so a cache error must fail closed.
        if (await isRevoked(state.cache, revokedKey)) throw REVOKED();
        return;
    }

    let cachedRevoked = false;
    try {
        cachedRevoked = Boolean(await state.cache.get(revokedKey));
    } catch (err) {
        // Storage is about to be asked anyway — a cache outage costs the
        // fast path, not availability.
        state.logger?.warn?.({ err }, 'Revocation cache unavailable — relying on the session store');
    }
    if (cachedRevoked) throw REVOKED();

    let session;
    try {
        session = await state.storage.sessionRepository.findByJti(payload.jti);
    } catch (cause) {
        throw new IdpError({ code: 'SESSION_STORE_UNAVAILABLE', httpStatus: 503, message: 'Unable to verify session status', cause });
    }
    if (!session || session.revokedAt || !(new Date(session.expiresAt) > new Date()) || String(session.user) !== String(payload.sub)) {
        throw REVOKED();
    }
}

function logRejection(req, err) {
    try {
        getState().logger?.warn?.({ err, path: req.originalUrl }, 'authContextMiddleware rejected request');
    } catch {
        // state not initialized — nothing to log through
    }
}
