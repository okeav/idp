import { getState } from '../config/state.js';
import { IdpError } from '../errors/idp-error.js';
import { verifyIssuedToken, isIdTokenPayload } from '../signing/token.service.js';
import { OAUTH_CLIENT_STATUS, CACHE_KEY_PREFIXES, COOKIE_NAMES, SESSION_KINDS } from '../config/constants.js';
import { auditLog } from '../hooks/index.js';
import { clearSessionCookies } from '../password-auth/controllers.js';
import { assertTrustedOrigin } from '../middleware/csrf.js';
import { readSessionCookie } from '../utils/cookies.js';
import { sessionKindOf } from '../utils/session-kind.js';
import { familyOf, peekRefreshRow, resolveRefreshTokenHash, revokeFamily } from '../utils/session-family.js';

/**
 * The browser's own first-party session row: the one behind its access token (`req.auth`) — or, once
 * that short-lived cookie has expired, the one behind its refresh cookie. Null when there is none.
 */
async function ownSessionRow(state, req) {
    const sessions = state.storage.sessionRepository;
    if (req.auth?.userId && req.auth.tokenMeta?.jti && !req.auth.tokenMeta.sessionless && typeof sessions.findByJti === 'function') {
        const row = await sessions.findByJti(req.auth.tokenMeta.jti);
        if (row && !row.revokedAt && String(row.user) === String(req.auth.userId)) return row;
    }
    const raw = readSessionCookie(state, req, COOKIE_NAMES.REFRESH_TOKEN);
    if (!raw) return null;
    const row = await peekRefreshRow(state, await resolveRefreshTokenHash(state, raw));
    return row && sessionKindOf(row) === SESSION_KINDS.FIRST_PARTY ? row : null;
}

/**
 * GET|POST /oidc/end-session — RP-initiated logout (OIDC RP-Initiated Logout 1.0).
 *
 * What it ends is deliberately narrow, because a GET is something any site can trigger:
 * - the browser's own IdP session (the first-party session whose cookie came with the request) —
 *   on a GET only with an `id_token_hint` for that same user (the relying party the user signed in
 *   to asked for it). Without one, a GET ends nothing and answers
 *   `{ action: 'logout_confirmation_required' }`: the IdP's frontend asks the user, then POSTs the
 *   same parameters (JSON or form) from a trusted origin (`cookies.trustedOrigins`) to end it;
 * - with an `id_token_hint` AND the browser signed in as that same user, the hinted relying party's
 *   sessions for that user. A hint alone ends nothing: ID tokens travel through URLs and logs, and
 *   whoever holds one must not be able to sign its user out of the relying party.
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
        const confirmed = req.method === 'POST';
        // A POST is the confirmation: it must come from the IdP's own pages (or a trusted frontend).
        if (confirmed) assertTrustedOrigin(state, req);
        const q = (confirmed ? req.body : req.query) ?? {};
        const idTokenHint = typeof q.id_token_hint === 'string' ? q.id_token_hint : undefined;
        const postLogoutRedirectUri = typeof q.post_logout_redirect_uri === 'string' ? q.post_logout_redirect_uri : undefined;
        const oidcState = typeof q.state === 'string' ? q.state : undefined;

        const own = await ownSessionRow(state, req);
        const signedInUserId = req.auth?.userId ?? (own ? String(own.user) : undefined);

        let hint = null;
        if (idTokenHint) {
            hint = verifyIssuedToken(state, idTokenHint, { issuer: state.config.issuer, ignoreExpiration: true });
            if (!isIdTokenPayload(state, hint)) throw new IdpError({ code: 'INVALID_REQUEST', httpStatus: 400, message: 'Invalid id_token_hint' });
            if (signedInUserId && String(signedInUserId) !== String(hint.sub)) {
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

        // Signed in, and nothing shows the user asked for this: ask them first — on the IdP's
        // confirmation page when one is configured (the browser was sent here by a relying party), with
        // the request's parameters so the page can POST them back.
        if (signedInUserId && !hint && !confirmed) {
            res.set('Cache-Control', 'no-store');
            const page = state.config.oidc?.endSessionConfirmationUrl;
            if (page) {
                const url = new URL(page);
                for (const [k, v] of Object.entries(q)) if (typeof v === 'string') url.searchParams.set(k, v);
                return res.redirect(url.toString());
            }
            return res.status(200).json({ action: 'logout_confirmation_required' });
        }

        const sessions = state.storage.sessionRepository;
        const revokedJtis = [];

        // The browser's own IdP session — its whole refresh family, so no rotated sibling carries on.
        if (own) {
            const revoked = await revokeFamily(state, familyOf(own).familyId, 'end_session');
            if (!revoked && (await sessions.revokeById(own.id, own.user)) && own.jti) revokedJtis.push(own.jti);
        }
        if (signedInUserId) clearSessionCookies(res, state);
        // The hinted relying party's sessions for this user — only on the user's own browser session.
        if (hint && signedInUserId && typeof sessions.revokeForClient === 'function') {
            const { jtis } = await sessions.revokeForClient(hint.aud, { userId: hint.sub });
            revokedJtis.push(...jtis);
        }
        for (const jti of revokedJtis) {
            await state.cache.set(`${CACHE_KEY_PREFIXES.REVOKED_REFRESH_TOKEN}:${jti}`, '1', state.config.ttls.revocationCache);
        }

        const userId = signedInUserId ?? hint?.sub;
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
