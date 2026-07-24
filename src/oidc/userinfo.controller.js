import { getState } from '../config/state.js';
import { IDENTITY_STATUS } from '../config/constants.js';

/** GET /userinfo — OIDC spec requires this exact path (not namespaced under /oidc). Requires a Bearer access token with the `openid` scope. */
export async function userinfoHandler(req, res) {
    if (!req.auth?.userId) {
        return res.status(401).set('WWW-Authenticate', 'Bearer error="invalid_token"').json({ error: 'invalid_token', error_description: 'The access token is missing or invalid' });
    }

    const state = getState();
    const user = await state.storage.userRepository.findById(req.auth.userId);
    if (!user) {
        return res.status(401).set('WWW-Authenticate', 'Bearer error="invalid_token"').json({ error: 'invalid_token', error_description: 'User not found' });
    }

    const scopes = (req.auth.claims?.scope || '').split(' ').filter(Boolean);
    const claims = { sub: String(user.id) };

    if (scopes.includes('email') || scopes.includes('openid')) {
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
        claims.updated_at = user.updatedAt ? Math.floor(user.updatedAt.getTime() / 1000) : undefined;
    }

    Object.keys(claims).forEach((k) => claims[k] === undefined && delete claims[k]);
    res.json(claims);
}
