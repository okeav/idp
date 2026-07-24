import { generateAuthenticationOptions } from '@simplewebauthn/server';
import { getState } from '../config/state.js';
import { IdpError } from '../errors/idp-error.js';
import { IDENTITY_STATUS } from '../config/constants.js';
import { getWebauthnConfig } from './config.js';
import { storeChallenge, consumeChallenge } from './challenge-store.js';
import { auditLog } from '../hooks/index.js';
import { verifyStoredCredentialAssertion } from './shared.js';
import { issueSession, setSessionCookies, resolveClaims } from '../password-auth/controllers.js';
import { verifyMfaChallengeToken as verifyMfaChallengeTokenJwt } from '../signing/token.service.js';

/**
 * Passkey as a *second factor* — an alternative to `verifyMfaChallengeHandler`
 * (TOTP) for completing the MFA gate `loginHandler` puts up when
 * `user.mfaEnabled`. Distinct from primary passwordless login
 * (authentication.controller.js) because the user is already partially
 * authenticated (password checked, `mfaChallengeToken` proves it) — so
 * unlike primary login, the server already knows exactly which user is
 * completing the ceremony and must verify the submitted credential actually
 * belongs to THAT user, not just that it's some valid registered passkey.
 */

function assertMfaChallenge(state, mfaChallengeToken) {
    try {
        return verifyMfaChallengeTokenJwt(state, mfaChallengeToken);
    } catch {
        throw new IdpError({ code: 'INVALID_MFA_CHALLENGE_TOKEN', httpStatus: 401, message: 'Invalid or expired MFA challenge token' });
    }
}

/** POST /webauthn/mfa/options */
export async function generateMfaWebauthnChallengeOptionsHandler(req, res, next) {
    try {
        const state = getState();
        const { rpID } = getWebauthnConfig(state);
        const { mfaChallengeToken } = req.body;

        const { sub: userId } = assertMfaChallenge(state, mfaChallengeToken);

        const credentials = await state.storage.credentialRepository.findByUserId(userId);
        if (credentials.length === 0) {
            throw new IdpError({ code: 'CREDENTIAL_NOT_FOUND', httpStatus: 400, message: 'No passkeys registered for this account' });
        }

        const options = await generateAuthenticationOptions({
            rpID,
            allowCredentials: credentials.map((c) => ({ id: c.credentialId, transports: c.transports })),
            // Discouraged (not "preferred"/"required") per SimpleWebAuthn's own
            // guidance for a 2FA step — the password already established user
            // presence/verification; re-demanding it here just adds friction.
            userVerification: 'discouraged',
        });

        await storeChallenge(state, `mfa-webauthn:${userId}`, options.challenge);

        res.json(options);
    } catch (err) {
        next(err);
    }
}

/** POST /webauthn/mfa/verify */
export async function verifyMfaWebauthnChallengeHandler(req, res, next) {
    try {
        const state = getState();
        const { mfaChallengeToken, response } = req.body;

        const { sub: userId } = assertMfaChallenge(state, mfaChallengeToken);

        const expectedChallenge = await consumeChallenge(state, `mfa-webauthn:${userId}`);
        if (!expectedChallenge) {
            throw new IdpError({ code: 'WEBAUTHN_CHALLENGE_EXPIRED', httpStatus: 400, message: 'MFA challenge expired or not found — restart login' });
        }

        const credentialDoc = await verifyStoredCredentialAssertion(state, { response, expectedChallenge });

        // Defense in depth: allowCredentials scoping in the browser should
        // already prevent this, but a malicious client could submit any
        // credential id in the assertion response — independently confirm the
        // verified credential belongs to the SAME user the password step
        // already authenticated, not merely some valid registered passkey.
        if (String(credentialDoc.user) !== String(userId)) {
            throw new IdpError({ code: 'WEBAUTHN_VERIFICATION_FAILED', httpStatus: 401, message: 'Credential does not belong to the challenged account' });
        }

        const user = await state.storage.userRepository.findById(userId);
        if (!user || user.status !== IDENTITY_STATUS.ACTIVE) {
            throw new IdpError({ code: 'USER_NOT_ACTIVE', httpStatus: 403, message: 'User account is not active' });
        }

        const claims = await resolveClaims(state, user, { isNewUser: false, method: 'webauthn-mfa' });
        const session = await issueSession(state, { user, claims, req });

        await auditLog(state.logger, state.hooks, 'MFA_VERIFIED', { userId, method: 'webauthn' });

        setSessionCookies(res, state, session);
        res.json({
            accessToken: session.accessToken.token,
            accessTokenExpiresAt: session.accessToken.expiresAt,
            refreshToken: session.refreshTokenValue,
            refreshTokenExpiresAt: session.refreshExpiresAt,
            userId,
        });
    } catch (err) {
        next(err);
    }
}
