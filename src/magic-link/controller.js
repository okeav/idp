import { getState } from '../config/state.js';
import { IdpError } from '../errors/idp-error.js';
import { IDENTITY_STATUS } from '../config/constants.js';
import { hashOpaqueToken, generateOpaqueToken } from '../signing/token.service.js';
import { auditLog, safeInvokeHook } from '../hooks/index.js';
import { enforceRateLimit } from '../rate-limit/enforce.js';
import { issueSession, setSessionCookies, resolveClaims, assertUsableStatus } from '../password-auth/controllers.js';

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

        await enforceRateLimit(state, `magic-link:ip:${req.ip}`, state.config.rateLimiting.magicLink);

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

        const token = generateOpaqueToken(32);
        await state.storage.verificationTokenRepository.create('magic_link', {
            user: user.id,
            tokenHash: hashOpaqueToken(state, token),
            expiresAt: new Date(Date.now() + state.config.ttls.magicLink * 1000),
        });

        await auditLog(state.logger, state.hooks, 'MAGIC_LINK_REQUESTED', { userId: String(user.id), email, isNewUser });
        await safeInvokeHook(state.logger, state.hooks, 'onMagicLinkRequested', {
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
        const { token } = req.body;

        const record = await state.storage.verificationTokenRepository.consumeByHash('magic_link', hashOpaqueToken(state, token));
        if (!record) throw new IdpError({ code: 'INVALID_OR_EXPIRED_TOKEN', httpStatus: 400, message: 'Invalid or expired magic link' });

        let user = await state.storage.userRepository.findById(record.user);
        if (!user) throw new IdpError({ code: 'USER_NOT_FOUND', httpStatus: 404, message: 'User not found' });

        const isNewUser = user.status === IDENTITY_STATUS.PENDING_VERIFICATION;
        if (isNewUser) {
            user = await state.storage.userRepository.updateById(user.id, { status: IDENTITY_STATUS.ACTIVE, failedLoginAttempts: 0, lockUntil: null });
        } else {
            assertUsableStatus(user);
        }

        const claims = await resolveClaims(state, user, { isNewUser, method: 'magic_link' });
        const session = await issueSession(state, { user, claims, req });

        await auditLog(state.logger, state.hooks, 'MAGIC_LINK_LOGIN', { userId: String(user.id), isNewUser });

        setSessionCookies(res, state, session);
        res.json({
            accessToken: session.accessToken.token,
            accessTokenExpiresAt: session.accessToken.expiresAt,
            refreshToken: session.refreshTokenValue,
            refreshTokenExpiresAt: session.refreshExpiresAt,
            userId: String(user.id),
            isNewUser,
        });
    } catch (err) {
        next(err);
    }
}
