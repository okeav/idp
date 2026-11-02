import crypto from 'crypto';
import { getState } from '../config/state.js';
import { IdpError } from '../errors/idp-error.js';
import { IDENTITY_STATUS, CACHE_KEY_PREFIXES } from '../config/constants.js';
import { isActiveAccount } from '../utils/account-status.js';
import { buildSsoProviders, normalizeUserInfo, exchangeCode, fetchUserInfo, assertAppleIdToken, decodeJwtPayload } from './providers.js';
import { ssoBindingCookie } from './binding.js';
import { readCookie } from '../utils/cookies.js';
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

        const param = (name) => {
            const v = req.query[name] ?? req.body?.[name];
            return typeof v === 'string' ? v : undefined;
        };
        const code = param('code');
        const csrfState = param('state');

        // The state is checked (and consumed, atomically) before anything else — including a provider
        // error — so nothing on this endpoint answers a request that this browser didn't start.
        const INVALID_STATE = () => new IdpError({ code: 'INVALID_SSO_STATE', httpStatus: 400, message: 'Invalid or expired SSO state' });
        if (!csrfState) throw INVALID_STATE();
        const stateData = await state.cache.take(`${CACHE_KEY_PREFIXES.SSO_STATE}:${csrfState}`);
        if (!stateData || stateData.provider !== provider) throw INVALID_STATE();

        const providers = buildSsoProviders(state.config);
        const providerConfig = providers[provider];
        if (!providerConfig) throw new IdpError({ code: 'INVALID_SSO_PROVIDER', httpStatus: 400, message: `Unknown SSO provider: ${provider}` });

        const cookie = ssoBindingCookie(state, csrfState, providerConfig);
        const binding = readCookie(req, cookie.name);
        res.clearCookie(cookie.name, { ...cookie.options, maxAge: undefined });
        if (typeof binding !== 'string' || !stateData.bindingHash || !safeEqual(sha256b64url(binding), stateData.bindingHash)) {
            state.logger?.warn?.({ provider }, 'SSO callback refused — not completed in the browser that started it');
            throw INVALID_STATE();
        }

        const { redirect_uri, extra } = stateData;
        const providerError = param('error');
        if (providerError) {
            // Only a sanitized error code travels back — never the provider's free-text description.
            return res.redirect(withParams(redirect_uri, { error: 'provider_error', provider_error: providerError.replace(/[^a-z_]/gi, '').slice(0, 64) }));
        }
        if (!code) return res.redirect(withParams(redirect_uri, { error: 'provider_error' }));

        const providerTokens = await exchangeCode(state.config, providerConfig, code, { codeVerifier: stateData.codeVerifier ?? undefined });

        let rawUserInfo;
        if (provider === 'apple') {
            let appleUser = null;
            const userParam = param('user');
            if (userParam) {
                try { appleUser = JSON.parse(userParam); } catch { /* name only sent on first authorization */ }
            }
            try {
                assertAppleIdToken(providerConfig, decodeJwtPayload(providerTokens.id_token), stateData.nonce);
            } catch (cause) {
                throw new IdpError({ code: 'SSO_PROVIDER_ERROR', httpStatus: 400, message: 'Apple id_token was not issued for this login', cause });
            }
            rawUserInfo = { id_token: providerTokens.id_token, appleUser };
        } else {
            rawUserInfo = await fetchUserInfo(state.config, providerConfig, providerTokens.access_token);
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
            if (isActiveAccount(existing)) {
                await users.linkExternalProvider(existing.id, link);
                user = await users.findById(existing.id);
                isNewLink = true;
            } else if (existing?.status === IDENTITY_STATUS.PENDING_VERIFICATION) {
                // The provider just proved ownership of an address someone registered here but never
                // verified. Whatever password that registration set is not the owner's (it may be an
                // attacker's pre-registration), so it is discarded as the owner claims the account.
                // Conditional on still being pending (an activation since the read must not be wiped);
                // either way the address is now owned by the provider-verified user and is linked below.
                const claimed = await users.updateByIdIfStatus(existing.id, IDENTITY_STATUS.PENDING_VERIFICATION, {
                    status: IDENTITY_STATUS.ACTIVE, failedLoginAttempts: 0, lockUntil: null,
                    passwordHash: null, registrationContested: false, mfaEnabled: false, mfaSecret: null, mfaTempSecret: null, mfaRecoveryCodes: [],
                });
                if (claimed) await state.storage.verificationTokenRepository.deleteAllForUser('email_verification', existing.id);
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

        if (!isActiveAccount(user)) {
            state.logger?.warn?.({ userId: user.id, provider, status: user.status }, 'SSO login blocked — account not active');
            return res.redirect(withParams(redirect_uri, { error: 'account_inactive' }));
        }

        if (isNewUser) await auditLog(state.logger, state.hooks, 'SSO_REGISTERED', { userId: String(user.id), provider });
        if (isNewLink) await auditLog(state.logger, state.hooks, 'SSO_PROVIDER_LINKED', { userId: String(user.id), provider });

        // SSO is one factor. An account with MFA still has to present it: hand back a challenge (in
        // the URL fragment, which never reaches a server log or a Referer header) instead of a session.
        if (user.mfaEnabled) {
            await auditLog(state.logger, state.hooks, 'SSO_MFA_REQUIRED', { userId: String(user.id), provider });
            const { mfaChallengeToken, expiresIn } = await mfaChallengeResponse(state, user, { loginChallenge: stateData.loginChallenge ?? undefined });
            return res.redirect(withParams(redirect_uri, { mfa_required: '1', mfa_challenge_token: mfaChallengeToken, expires_in: String(expiresIn) }, { fragment: true }));
        }

        await auditLog(state.logger, state.hooks, 'SSO_LOGIN', { userId: String(user.id), provider });

        const claims = await resolveClaims(state, user, { isNewUser, isNewLink, provider, extra });
        const session = await issueSession(state, { user, claims, req, loginChallenge: stateData.loginChallenge ?? undefined });

        setSessionCookies(req, res, state, session);
        res.redirect(withParams(redirect_uri, { ssoLogin: 'success' }));
    } catch (err) {
        next(err);
    }
}

const sha256b64url = (s) => crypto.createHash('sha256').update(s).digest('base64url');

function safeEqual(a, b) {
    const x = Buffer.from(String(a));
    const y = Buffer.from(String(b));
    return x.length === y.length && crypto.timingSafeEqual(x, y);
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
