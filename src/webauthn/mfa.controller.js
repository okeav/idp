import { generateAuthenticationOptions } from '@simplewebauthn/server';
import { getState } from '../config/state.js';
import { assertTrustedOrigin } from '../middleware/csrf.js';
import { IdpError } from '../errors/idp-error.js';
import { isActiveAccount } from '../utils/account-status.js';
import { getWebauthnConfig } from './config.js';
import { storeChallenge, consumeChallenge } from './challenge-store.js';
import { auditLog } from '../hooks/index.js';
import { verifyStoredCredentialAssertion } from './shared.js';
import { issueSession, setSessionCookies, resolveClaims, refreshTokenInBody } from '../password-auth/controllers.js';
import { enforceRateLimit } from '../rate-limit/enforce.js';
import { ipKey } from '../rate-limit/keys.js';
import { guardMfaAttempt } from '../mfa/attempt-guard.js';
import { verifyChallengeToken, assertChallengeCurrent, spendChallenge } from '../mfa/controller.js';

// A failed assertion is a failed second-factor attempt, counted against the
// same per-account limit as a wrong TOTP/recovery code. An expired or missing
// challenge isn't — no guess was made.
const ASSERTION_FAILURE_CODES = new Set(['WEBAUTHN_VERIFICATION_FAILED', 'CREDENTIAL_NOT_FOUND', 'INVALID_REQUEST']);
const isAssertionFailure = (err) => ASSERTION_FAILURE_CODES.has(err?.code);

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

/** POST /webauthn/mfa/options */
export async function generateMfaWebauthnChallengeOptionsHandler(req, res, next) {
    try {
        const state = getState();
        const { rpID } = getWebauthnConfig(state);
        const { mfaChallengeToken } = req.body;

        const { sub: userId } = verifyChallengeToken(state, mfaChallengeToken);

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
        assertTrustedOrigin(state, req); // sets session cookies — refuse login CSRF (see middleware/csrf.js)
        const { mfaChallengeToken, response } = req.body;

        await enforceRateLimit(state, `mfa-challenge:ip:${ipKey(req.ip)}`, state.config.rateLimiting.mfaChallenge, { failMode: 'closed' });

        const challenge = verifyChallengeToken(state, mfaChallengeToken);
        const userId = challenge.sub;
        const user = await state.storage.userRepository.findById(userId);
        if (!isActiveAccount(user)) {
            throw new IdpError({ code: 'USER_NOT_ACTIVE', httpStatus: 403, message: 'User account is not active' });
        }
        assertChallengeCurrent(user, challenge);

        await guardMfaAttempt(state, userId, { method: 'webauthn', isFailure: isAssertionFailure }, async () => {
            const expectedChallenge = await consumeChallenge(state, `mfa-webauthn:${userId}`);
            if (!expectedChallenge) {
                throw new IdpError({ code: 'WEBAUTHN_CHALLENGE_EXPIRED', httpStatus: 400, message: 'MFA challenge expired or not found — restart login' });
            }

            // Matches the options' `userVerification: 'discouraged'`: the password was the knowledge
            // factor, so a PIN-less security key (presence only) is a valid second factor here.
            const credentialDoc = await verifyStoredCredentialAssertion(state, { response, expectedChallenge, requireUserVerification: false });

            // Defense in depth: allowCredentials scoping in the browser should
            // already prevent this, but a malicious client could submit any
            // credential id in the assertion response — independently confirm the
            // verified credential belongs to the SAME user the password step
            // already authenticated, not merely some valid registered passkey.
            if (String(credentialDoc.user) !== String(userId)) {
                throw new IdpError({ code: 'WEBAUTHN_VERIFICATION_FAILED', httpStatus: 401, message: 'Credential does not belong to the challenged account' });
            }
        });

        await spendChallenge(state, challenge);

        const claims = await resolveClaims(state, user, { isNewUser: false, method: 'webauthn-mfa' });
        const session = await issueSession(state, { user, claims, req, sessionEpoch: challenge.sep });

        await auditLog(state.logger, state.hooks, 'MFA_VERIFIED', { userId, method: 'webauthn' });

        setSessionCookies(res, state, session);
        res.json({
            accessToken: session.accessToken.token,
            accessTokenExpiresAt: session.accessToken.expiresAt,
            ...refreshTokenInBody(state, req, session.refreshTokenValue),
            refreshTokenExpiresAt: session.refreshExpiresAt,
            userId,
        });
    } catch (err) {
        next(err);
    }
}
