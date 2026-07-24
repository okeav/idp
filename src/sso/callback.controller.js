import { getState } from '../config/state.js';
import { IdpError } from '../errors/idp-error.js';
import { IDENTITY_STATUS, CACHE_KEY_PREFIXES } from '../config/constants.js';
import { buildSsoProviders, normalizeUserInfo, exchangeCode, fetchUserInfo } from './providers.js';
import { auditLog } from '../hooks/index.js';
import { issueSession, setSessionCookies, resolveClaims } from '../password-auth/controllers.js';

/**
 * GET/POST /sso/:provider/callback
 *
 * Collapsed to a single step (Phase 2 decision): the audited source issued a
 * short-lived exchange token here and made a second service redeem it for an
 * enriched session. That split existed only because Okeav's account-service
 * (not auth-service) resolved role/scopes/accountId — it wasn't a redirect-
 * URI or CSRF security requirement (the CSRF-relevant `state` check happens
 * entirely above, before any token is minted). This version calls
 * `hooks.resolveAuthContext` synchronously and mints the full session
 * directly. A consumer who wants Okeav's two-service split can still get it
 * by having `resolveAuthContext` itself return a pointer and complete
 * enrichment out-of-band — that's a hook implementation choice now, not
 * something the package hardcodes.
 */
export async function ssoCallbackHandler(req, res, next) {
    try {
        const state = getState();
        const { provider } = req.params;

        const code = req.query.code ?? req.body?.code;
        const csrfState = req.query.state ?? req.body?.state;
        const providerError = req.query.error ?? req.body?.error;
        const providerErrorDescription = req.query.error_description ?? req.body?.error_description;

        if (providerError) {
            return res.status(400).json({ error: providerError, error_description: providerErrorDescription });
        }

        const stateKey = `${CACHE_KEY_PREFIXES.SSO_STATE}:${csrfState}`;
        const stateData = await state.cache.get(stateKey);
        if (!stateData || stateData.provider !== provider) {
            throw new IdpError({ code: 'INVALID_SSO_STATE', httpStatus: 400, message: 'Invalid or expired SSO state' });
        }
        await state.cache.del(stateKey);

        const { redirect_uri, extra } = stateData;
        const providers = buildSsoProviders(state.config);
        const providerConfig = providers[provider];
        if (!providerConfig) throw new IdpError({ code: 'INVALID_SSO_PROVIDER', httpStatus: 400, message: `Unknown SSO provider: ${provider}` });

        const providerTokens = await exchangeCode(providerConfig, code);

        let rawUserInfo;
        if (provider === 'apple') {
            let appleUser = null;
            if (req.body?.user) {
                try { appleUser = JSON.parse(req.body.user); } catch { /* name only sent on first authorization */ }
            }
            rawUserInfo = { id_token: providerTokens.id_token, appleUser };
        } else {
            rawUserInfo = await fetchUserInfo(providerConfig, providerTokens.access_token);
        }

        const userInfo = normalizeUserInfo(provider, rawUserInfo);
        if (!userInfo.email) {
            state.logger?.warn?.({ provider }, 'SSO provider did not return an email address');
            return res.redirect(`${redirect_uri}?error=email_required`);
        }

        let user = await state.storage.userRepository.findByExternalProvider(provider, userInfo.providerId);
        let isNewUser = false;
        let isNewLink = false;

        if (!user) {
            user = await state.storage.userRepository.findByEmail(userInfo.email);
            if (user) {
                await state.storage.userRepository.linkExternalProvider(user.id, { provider, providerId: userInfo.providerId, email: userInfo.email, connectedAt: new Date() });
                isNewLink = true;
            } else {
                user = await state.storage.userRepository.create({
                    email: userInfo.email.toLowerCase(),
                    status: IDENTITY_STATUS.ACTIVE, // trusted provider — treated as verified
                    profile: { firstName: userInfo.firstName, lastName: userInfo.lastName, displayName: userInfo.name, avatarUrl: userInfo.avatarUrl },
                    externalProviders: [{ provider, providerId: userInfo.providerId, email: userInfo.email, connectedAt: new Date() }],
                });
                isNewUser = true;
            }
        }

        if (user.status !== IDENTITY_STATUS.ACTIVE) {
            state.logger?.warn?.({ userId: user.id, provider, status: user.status }, 'SSO login blocked — account not active');
            return res.redirect(`${redirect_uri}?error=account_inactive`);
        }

        if (isNewUser) await auditLog(state.logger, state.hooks, 'SSO_REGISTERED', { userId: String(user.id), provider });
        if (isNewLink) await auditLog(state.logger, state.hooks, 'SSO_PROVIDER_LINKED', { userId: String(user.id), provider });
        await auditLog(state.logger, state.hooks, 'SSO_LOGIN', { userId: String(user.id), provider });

        const claims = await resolveClaims(state, user, { isNewUser, isNewLink, provider, extra });
        const session = await issueSession(state, { user, claims, req });

        setSessionCookies(res, state, session);
        const successUrl = new URL(redirect_uri);
        successUrl.searchParams.set('ssoLogin', 'success');
        res.redirect(successUrl.toString());
    } catch (err) {
        next(err);
    }
}
