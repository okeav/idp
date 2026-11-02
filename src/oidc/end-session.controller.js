import { getState } from '../config/state.js';
import { IdpError } from '../errors/idp-error.js';
import { verifyIssuedToken, isIdTokenPayload } from '../signing/token.service.js';
import { OAUTH_CLIENT_STATUS, CACHE_KEY_PREFIXES } from '../config/constants.js';
import { auditLog } from '../hooks/index.js';
import { clearSessionCookies } from '../password-auth/controllers.js';

/**
 * GET /oidc/end-session — RP-initiated logout (OIDC RP-Initiated Logout 1.0).
 *
 * What it ends is deliberately narrow, because the request is a plain GET any site can trigger:
 * - the browser's own IdP session (the first-party session whose cookie came with the request), and
 * - with an `id_token_hint`, the hinted relying party's sessions for that user.
 * It never signs the user out of every device: an ID token is handed to every relying party, so
 * possessing one — or tricking a browser into this URL — must not be a kill switch for all of the
 * user's sessions. "Log out everywhere" remains `POST /logout/all`.
 *
 * `id_token_hint` must be an ID token this IdP issued (an access or MFA-challenge token is refused);
 * an expired one is accepted, as the spec recommends. `post_logout_redirect_uri` must be registered
 * to the hinted client.
 */
export async function endSessionHandler(req, res, next) {
    try {
        const state = getState();
        const q = req.query;
        const idTokenHint = typeof q.id_token_hint === 'string' ? q.id_token_hint : undefined;
        const postLogoutRedirectUri = typeof q.post_logout_redirect_uri === 'string' ? q.post_logout_redirect_uri : undefined;
        const oidcState = typeof q.state === 'string' ? q.state : undefined;

        let hint = null;
        if (idTokenHint) {
            hint = verifyIssuedToken(state, idTokenHint, { issuer: state.config.issuer, ignoreExpiration: true });
            if (!isIdTokenPayload(state, hint)) throw new IdpError({ code: 'INVALID_REQUEST', httpStatus: 400, message: 'Invalid id_token_hint' });
            if (req.auth?.userId && String(req.auth.userId) !== String(hint.sub)) {
                throw new IdpError({ code: 'INVALID_REQUEST', httpStatus: 400, message: 'id_token_hint does not belong to the signed-in user' });
            }
        }

        if (postLogoutRedirectUri) {
            if (!hint) {
                throw new IdpError({ code: 'INVALID_REQUEST', httpStatus: 400, message: 'id_token_hint is required when post_logout_redirect_uri is supplied' });
            }
            const client = await state.storage.oauthClientRepository.findByClientId(hint.aud);
            if (!client || client.status !== OAUTH_CLIENT_STATUS.ACTIVE) {
                throw new IdpError({ code: 'OAUTH_CLIENT_NOT_FOUND', httpStatus: 400, message: 'Unknown or inactive client' });
            }
            const allowed = client.postLogoutRedirectUris?.length ? client.postLogoutRedirectUris : client.redirectUris;
            if (!allowed?.includes(postLogoutRedirectUri)) {
                throw new IdpError({ code: 'INVALID_REDIRECT_URI', httpStatus: 400, message: 'post_logout_redirect_uri is not registered for this client' });
            }
        }

        const sessions = state.storage.sessionRepository;
        const revokedJtis = [];

        // The browser's own IdP session.
        if (req.auth?.userId && req.auth.tokenMeta?.jti && typeof sessions.findByJti === 'function') {
            const own = await sessions.findByJti(req.auth.tokenMeta.jti);
            if (own && !own.revokedAt && (await sessions.revokeById(own.id, req.auth.userId))) revokedJtis.push(req.auth.tokenMeta.jti);
            clearSessionCookies(res, state);
        }
        // The hinted relying party's sessions for this user.
        if (hint && typeof sessions.revokeForClient === 'function') {
            const { jtis } = await sessions.revokeForClient(hint.aud, { userId: hint.sub });
            revokedJtis.push(...jtis);
        }
        for (const jti of revokedJtis) {
            await state.cache.set(`${CACHE_KEY_PREFIXES.REVOKED_REFRESH_TOKEN}:${jti}`, '1', state.config.ttls.revocationCache);
        }

        const userId = req.auth?.userId ?? hint?.sub;
        if (userId) await auditLog(state.logger, state.hooks, 'END_SESSION', { userId: String(userId), clientId: hint?.aud ?? null, revokedSessions: revokedJtis.length });

        if (postLogoutRedirectUri) {
            const redirectUrl = new URL(postLogoutRedirectUri);
            if (oidcState) redirectUrl.searchParams.set('state', oidcState);
            return res.redirect(redirectUrl.toString());
        }

        res.json({ status: 'ok' });
    } catch (err) {
        next(err);
    }
}
