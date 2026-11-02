import { getState } from '../config/state.js';
import { assertTrustedOrigin } from '../middleware/csrf.js';
import { IdpError } from '../errors/idp-error.js';
import { IDENTITY_STATUS } from '../config/constants.js';
import { hashOpaqueToken, generateOpaqueToken, lookupByTokenHash, HASH_PURPOSES } from '../signing/token.service.js';
import { auditLog, auditLogDetached, invokeHookDetached } from '../hooks/index.js';
import { enforceRateLimit } from '../rate-limit/enforce.js';
import { ipKey, emailKey } from '../rate-limit/keys.js';
import { issueSession, setSessionCookies, resolveClaims, assertUsableStatus, mfaChallengeResponse, refreshTokenInBody } from '../password-auth/controllers.js';

/**
 * POST /magic-link/request
 *
 * Enumeration-safe: always responds `{ status: 'ok' }` regardless of whether
 * the email belongs to an existing account, a newly-created one, or neither.
 * When `config.magicLink.allowSignupViaMagicLink` is true (the default), an
 * unknown email creates a new (passwordless) user in PENDING_VERIFICATION —
 * the same state a password-based registration starts in — which
 * `verifyMagicLinkHandler` promotes to ACTIVE on first successful click,
 * exactly mirroring the register→verify-email flow but collapsed into one
 * link instead of two steps.
 */
export async function requestMagicLinkHandler(req, res, next) {
    try {
        const state = getState();
        const { email } = req.body;

        await enforceRateLimit(state, `magic-link:ip:${ipKey(req.ip)}`, state.config.rateLimiting.magicLink, { failMode: 'closed' });
        // Per address too: per-IP alone lets a distributed sender flood one inbox.
        await enforceRateLimit(state, `magic-link:email:${emailKey(state, email)}`, state.config.rateLimiting.magicLinkByEmail, { failMode: 'closed' });

        let user = await state.storage.userRepository.findByEmail(email);
        let isNewUser = false;

        if (!user) {
            if (!state.config.magicLink.allowSignupViaMagicLink) {
                return res.json({ status: 'ok' }); // invite-only mode — stay enumeration-safe, no link issued
            }
            user = await state.storage.userRepository.create({ email, status: IDENTITY_STATUS.PENDING_VERIFICATION, profile: {} });
            isNewUser = true;
        } else if (user.status === IDENTITY_STATUS.DELETED) {
            return res.json({ status: 'ok' }); // don't resurrect a deleted account via magic link
        }

        // Only the newest link works: requesting another replaces the earlier one (atomically).
        const token = generateOpaqueToken(32);
        await state.storage.verificationTokenRepository.replaceForUser('magic_link', user.id, {
            tokenHash: hashOpaqueToken(state, token, HASH_PURPOSES.MAGIC_LINK),
            expiresAt: new Date(Date.now() + state.config.ttls.magicLink * 1000),
        });

        auditLogDetached(state.logger, state.hooks, 'MAGIC_LINK_REQUESTED', { userId: String(user.id), email, isNewUser });
        invokeHookDetached(state.logger, state.hooks, 'onMagicLinkRequested', {
            email, magicLinkToken: token, firstName: user.profile?.firstName, lastName: user.profile?.lastName, isNewUser,
        });

        res.json({ status: 'ok' });
    } catch (err) {
        next(err);
    }
}

/**
 * POST /magic-link/verify
 *
 * Consumes the token and issues a full session through the same
 * `resolveAuthContext` + `issueSession` path every other login method uses —
 * magic-link login is not a shortcut around claims resolution.
 */
export async function verifyMagicLinkHandler(req, res, next) {
    try {
        const state = getState();
        assertTrustedOrigin(state, req); // sets session cookies — refuse login CSRF (see middleware/csrf.js)
        const { token } = req.body;

        const { result: record } = await lookupByTokenHash(state, token, HASH_PURPOSES.MAGIC_LINK, (hash) => state.storage.verificationTokenRepository.consumeByHash('magic_link', hash));
        if (!record) throw new IdpError({ code: 'INVALID_OR_EXPIRED_TOKEN', httpStatus: 400, message: 'Invalid or expired magic link' });

        let user = await state.storage.userRepository.findById(record.user);
        if (!user) throw new IdpError({ code: 'USER_NOT_FOUND', httpStatus: 404, message: 'User not found' });

        const isNewUser = user.status === IDENTITY_STATUS.PENDING_VERIFICATION;
        if (isNewUser) {
            // Clicking the link proves ownership of the address — but NOT of any password set on this
            // still-unverified account, which anyone could have registered with. Activating it with that
            // password intact hands the account to whoever pre-registered the victim's email; it is
            // discarded instead (the owner can set one through password reset).
            // Conditional on still being pending: if the account was activated meanwhile (with whatever
            // password its owner verified), it must not be wiped — it is then just a sign-in.
            const activated = await state.storage.userRepository.updateByIdIfStatus(user.id, IDENTITY_STATUS.PENDING_VERIFICATION, {
                status: IDENTITY_STATUS.ACTIVE, failedLoginAttempts: 0, lockUntil: null,
                passwordHash: null, registrationContested: false, mfaEnabled: false, mfaSecret: null, mfaTempSecret: null, mfaRecoveryCodes: [],
            });
            if (activated) {
                user = activated;
                await state.storage.verificationTokenRepository.deleteAllForUser('email_verification', user.id);
            } else {
                user = await state.storage.userRepository.findById(record.user);
                if (!user) throw new IdpError({ code: 'USER_NOT_FOUND', httpStatus: 404, message: 'User not found' });
                assertUsableStatus(user);
            }
        } else {
            assertUsableStatus(user);
        }

        // A magic link is one factor (the inbox). An account with MFA still has to present it.
        if (user.mfaEnabled) {
            await auditLog(state.logger, state.hooks, 'MAGIC_LINK_MFA_REQUIRED', { userId: String(user.id) });
            return res.json(await mfaChallengeResponse(state, user, { loginChallenge: req.body.login_challenge }));
        }

        const claims = await resolveClaims(state, user, { isNewUser, method: 'magic_link' });
        const session = await issueSession(state, { user, claims, req, loginChallenge: req.body.login_challenge });

        await auditLog(state.logger, state.hooks, 'MAGIC_LINK_LOGIN', { userId: String(user.id), isNewUser });

        setSessionCookies(req, res, state, session);
        res.json({
            accessToken: session.accessToken.token,
            accessTokenExpiresAt: session.accessToken.expiresAt,
            ...refreshTokenInBody(state, req, session.refreshTokenValue),
            refreshTokenExpiresAt: session.refreshExpiresAt,
            userId: String(user.id),
            isNewUser,
        });
    } catch (err) {
        next(err);
    }
}
