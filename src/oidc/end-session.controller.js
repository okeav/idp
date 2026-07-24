import { getState } from '../config/state.js';
import { IdpError } from '../errors/idp-error.js';
import { verifyIssuedToken } from '../signing/token.service.js';
import { OAUTH_CLIENT_STATUS } from '../config/constants.js';
import { auditLog } from '../hooks/index.js';

/** GET /oidc/end-session — RP-initiated logout (OIDC session-management). */
export async function endSessionHandler(req, res, next) {
    try {
        const state = getState();
        const { post_logout_redirect_uri, state: oidcState, id_token_hint } = req.query;

        let userId = req.auth?.userId || null;
        let hintClaims = null;
        if (id_token_hint) {
            hintClaims = verifyIssuedToken(state, id_token_hint, { issuer: state.config.issuer });
            if (!hintClaims) throw new IdpError({ code: 'INVALID_REQUEST', httpStatus: 400, message: 'Invalid id_token_hint' });
            userId = userId || hintClaims.sub;
        }

        if (post_logout_redirect_uri) {
            if (!hintClaims?.aud) {
                throw new IdpError({ code: 'INVALID_REQUEST', httpStatus: 400, message: 'id_token_hint is required when post_logout_redirect_uri is supplied' });
            }
            const client = await state.storage.oauthClientRepository.findByClientId(hintClaims.aud);
            if (!client || client.status !== OAUTH_CLIENT_STATUS.ACTIVE) {
                throw new IdpError({ code: 'OAUTH_CLIENT_NOT_FOUND', httpStatus: 400, message: 'Unknown or inactive client' });
            }
            const allowed = client.postLogoutRedirectUris?.length ? client.postLogoutRedirectUris : client.redirectUris;
            if (!allowed?.includes(post_logout_redirect_uri)) {
                throw new IdpError({ code: 'INVALID_REDIRECT_URI', httpStatus: 400, message: 'post_logout_redirect_uri is not registered for this client' });
            }
        }

        if (userId) {
            const result = await state.storage.sessionRepository.revokeAllForUser(userId);
            await auditLog(state.logger, state.hooks, 'END_SESSION', { userId, revokedSessions: result.revokedCount });
        }

        if (post_logout_redirect_uri) {
            const redirectUrl = new URL(post_logout_redirect_uri);
            if (oidcState) redirectUrl.searchParams.set('state', oidcState);
            return res.redirect(redirectUrl.toString());
        }

        res.json({ status: 'ok' });
    } catch (err) {
        next(err);
    }
}
