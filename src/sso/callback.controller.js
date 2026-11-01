import { getState } from '../config/state.js';
import { IdpError } from '../errors/idp-error.js';
import { IDENTITY_STATUS, CACHE_KEY_PREFIXES } from '../config/constants.js';
import { buildSsoProviders, normalizeUserInfo, exchangeCode, fetchUserInfo } from './providers.js';
import { auditLog } from '../hooks/index.js';
import { issueSession, setSessionCookies, resolveClaims, mfaChallengeResponse } from '../password-auth/controllers.js';

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

        const userInfo = normalizeUserInfo(provider, rawUserInfo, providerConfig);
        if (!userInfo.email) {
            state.logger?.warn?.({ provider }, 'SSO provider did not return an email address');
            return res.redirect(withParams(redirect_uri, { error: 'email_required' }));
        }

        const users = state.storage.userRepository;
        let user = await users.findByExternalProvider(provider, userInfo.providerId);
        let isNewUser = false;
        let isNewLink = false;

        if (!user) {
            // Matching by email links this provider identity to whoever owns the address here — so the
            // provider must vouch that the address is verified. Otherwise anyone who can put an
            // arbitrary email on a provider account (e.g. a Microsoft tenant admin) logs in as its owner.
            if (!userInfo.emailVerified) {
                state.logger?.warn?.({ provider }, 'SSO login refused — provider did not assert a verified email');
                return res.redirect(withParams(redirect_uri, { error: 'email_not_verified' }));
            }

            const link = { provider, providerId: userInfo.providerId, email: userInfo.email, connectedAt: new Date() };
            const existing = await users.findByEmail(userInfo.email);
            if (existing?.status === IDENTITY_STATUS.ACTIVE) {
                await users.linkExternalProvider(existing.id, link);
                user = await users.findById(existing.id);
                isNewLink = true;
            } else if (existing?.status === IDENTITY_STATUS.PENDING_VERIFICATION) {
                // The provider just proved ownership of an address someone registered here but never
                // verified. Whatever password that registration set is not the owner's (it may be an
                // attacker's pre-registration), so it is discarded as the owner claims the account.
                await users.updateById(existing.id, {
                    status: IDENTITY_STATUS.ACTIVE, failedLoginAttempts: 0, lockUntil: null,
                    passwordHash: null, mfaEnabled: false, mfaSecret: null, mfaTempSecret: null, mfaRecoveryCodes: [],
                });
                await state.storage.verificationTokenRepository.deleteAllForUser('email_verification', existing.id);
                await users.linkExternalProvider(existing.id, link);
                user = await users.findById(existing.id);
                isNewLink = true;
                await auditLog(state.logger, state.hooks, 'SSO_PENDING_ACCOUNT_CLAIMED', { userId: String(user.id), provider });
            } else if (existing) {
                // Locked, suspended, deleted …: never attach a new login method to it.
                state.logger?.warn?.({ userId: existing.id, provider, status: existing.status }, 'SSO login blocked — account not active');
                return res.redirect(withParams(redirect_uri, { error: 'account_inactive' }));
            } else {
                user = await users.create({
                    email: userInfo.email.toLowerCase(),
                    status: IDENTITY_STATUS.ACTIVE, // the provider verified the address
                    profile: { firstName: userInfo.firstName, lastName: userInfo.lastName, displayName: userInfo.name, avatarUrl: userInfo.avatarUrl },
                    externalProviders: [link],
                });
                isNewUser = true;
            }
        }

        if (user.status !== IDENTITY_STATUS.ACTIVE) {
            state.logger?.warn?.({ userId: user.id, provider, status: user.status }, 'SSO login blocked — account not active');
            return res.redirect(withParams(redirect_uri, { error: 'account_inactive' }));
        }

        if (isNewUser) await auditLog(state.logger, state.hooks, 'SSO_REGISTERED', { userId: String(user.id), provider });
        if (isNewLink) await auditLog(state.logger, state.hooks, 'SSO_PROVIDER_LINKED', { userId: String(user.id), provider });

        // SSO is one factor. An account with MFA still has to present it: hand back a challenge (in
        // the URL fragment, which never reaches a server log or a Referer header) instead of a session.
        if (user.mfaEnabled) {
            await auditLog(state.logger, state.hooks, 'SSO_MFA_REQUIRED', { userId: String(user.id), provider });
            const { mfaChallengeToken, expiresIn } = await mfaChallengeResponse(state, user);
            return res.redirect(withParams(redirect_uri, { mfa_required: '1', mfa_challenge_token: mfaChallengeToken, expires_in: String(expiresIn) }, { fragment: true }));
        }

        await auditLog(state.logger, state.hooks, 'SSO_LOGIN', { userId: String(user.id), provider });

        const claims = await resolveClaims(state, user, { isNewUser, isNewLink, provider, extra });
        const session = await issueSession(state, { user, claims, req });

        setSessionCookies(res, state, session);
        res.redirect(withParams(redirect_uri, { ssoLogin: 'success' }));
    } catch (err) {
        next(err);
    }
}

/** Adds params to a URL that may already carry a query string (or, with `fragment`, to its fragment). */
function withParams(uri, params, { fragment = false } = {}) {
    const url = new URL(uri);
    if (fragment) {
        url.hash = new URLSearchParams(params).toString();
    } else {
        for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);
    }
    return url.toString();
}
