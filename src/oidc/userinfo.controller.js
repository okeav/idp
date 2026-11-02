import { getState } from '../config/state.js';
import { IDENTITY_STATUS } from '../config/constants.js';
import { isActiveAccount } from '../utils/account-status.js';

function invalidToken(res, description) {
    return res.status(401).set('WWW-Authenticate', 'Bearer error="invalid_token"').json({ error: 'invalid_token', error_description: description });
}

/**
 * GET /userinfo — OIDC spec requires this exact path (not namespaced under /oidc). Requires an
 * OAuth2 access token issued on behalf of a user (`authContextMiddleware({ accept: ['oauth2-user'] })`)
 * carrying the `openid` scope. Claims are released per granted scope only (OIDC Core §5.4).
 */
export async function userinfoHandler(req, res, next) {
    try {
        if (!req.auth?.userId) return invalidToken(res, 'The access token is missing or invalid');

        const scopes = req.auth.scopes ?? String(req.auth.claims?.scope || '').split(' ').filter(Boolean);
        if (!scopes.includes('openid')) {
            return res.status(403).set('WWW-Authenticate', 'Bearer error="insufficient_scope", scope="openid"').json({ error: 'insufficient_scope', error_description: 'The openid scope is required' });
        }

        const state = getState();
        const user = await state.storage.userRepository.findById(req.auth.userId);
        if (!isActiveAccount(user)) return invalidToken(res, 'User not found');

        const claims = { sub: String(user.id) };

        if (scopes.includes('email')) {
            claims.email = user.email;
            claims.email_verified = user.status !== IDENTITY_STATUS.PENDING_VERIFICATION;
        }
        if (scopes.includes('profile')) {
            claims.name = user.profile?.displayName || `${user.profile?.firstName || ''} ${user.profile?.lastName || ''}`.trim() || undefined;
            claims.given_name = user.profile?.firstName || undefined;
            claims.family_name = user.profile?.lastName || undefined;
            claims.picture = user.profile?.avatarUrl || undefined;
            claims.locale = user.profile?.locale || undefined;
            claims.zoneinfo = user.profile?.zoneinfo || undefined;
            claims.updated_at = user.updatedAt ? Math.floor(new Date(user.updatedAt).getTime() / 1000) : undefined;
        }

        Object.keys(claims).forEach((k) => claims[k] === undefined && delete claims[k]);
        res.set('Cache-Control', 'no-store');
        res.json(claims);
    } catch (err) {
        next(err);
    }
}
