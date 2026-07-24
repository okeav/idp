import { generateAuthenticationOptions } from '@simplewebauthn/server';
import { getState } from '../config/state.js';
import { IdpError } from '../errors/idp-error.js';
import { getWebauthnConfig } from './config.js';
import { storeChallenge, consumeChallenge } from './challenge-store.js';
import { auditLog } from '../hooks/index.js';
import { verifyStoredCredentialAssertion } from './shared.js';
import { issueSession, setSessionCookies, resolveClaims, assertUsableStatus } from '../password-auth/controllers.js';

/**
 * Primary/passwordless login — no prior session or password required. This
 * is a genuinely different starting point than the MFA-second-factor flow
 * (src/webauthn/mfa.controller.js): here, WHICH user is authenticating is
 * established entirely by the credential ID in the assertion response
 * (globally unique per the WebAuthn spec) — there's no `mfaChallengeToken`
 * or prior password check identifying them first.
 *
 * The pending challenge has no natural "known user" key to store it under
 * for a usernameless ceremony, so it's keyed by the challenge value itself
 * (decoded back out of the assertion response at verify time) rather than a
 * userId — the same approach registration/MFA use where the user IS already
 * known.
 */
function decodeChallengeFromResponse(response) {
    try {
        const clientDataJSON = JSON.parse(Buffer.from(response.response.clientDataJSON, 'base64url').toString('utf8'));
        return clientDataJSON.challenge || null;
    } catch {
        return null;
    }
}

/** POST /webauthn/authentication/options — `email` is optional; omit it for a usernameless/discoverable-credential challenge (the browser lets the user pick which passkey to use). */
export async function generateAuthenticationOptionsHandler(req, res, next) {
    try {
        const state = getState();
        const { rpID } = getWebauthnConfig(state);
        const { email } = req.body || {};

        let allowCredentials;
        if (email) {
            const user = await state.storage.userRepository.findByEmail(email);
            // Enumeration-safe: an unknown email still gets a real (if
            // uncompletable) challenge rather than a distinguishable error.
            const credentials = user ? await state.storage.credentialRepository.findByUserId(user.id) : [];
            allowCredentials = credentials.map((c) => ({ id: c.credentialId, transports: c.transports }));
        }

        const options = await generateAuthenticationOptions({ rpID, allowCredentials, userVerification: 'preferred' });

        await storeChallenge(state, `authn:${options.challenge}`, true);

        res.json(options);
    } catch (err) {
        next(err);
    }
}

/** POST /webauthn/authentication/verify — issues a full session through the same resolveAuthContext + issueSession path every other login method uses. */
export async function verifyAuthenticationHandler(req, res, next) {
    try {
        const state = getState();
        const { response } = req.body;

        const challenge = decodeChallengeFromResponse(response);
        if (!challenge) throw new IdpError({ code: 'INVALID_REQUEST', httpStatus: 400, message: 'Malformed WebAuthn assertion response' });

        const consumed = await consumeChallenge(state, `authn:${challenge}`);
        if (!consumed) throw new IdpError({ code: 'WEBAUTHN_CHALLENGE_EXPIRED', httpStatus: 400, message: 'Authentication challenge expired or not found — restart login' });

        const credentialDoc = await verifyStoredCredentialAssertion(state, { response, expectedChallenge: challenge });

        const user = await state.storage.userRepository.findById(credentialDoc.user);
        if (!user) throw new IdpError({ code: 'USER_NOT_FOUND', httpStatus: 404, message: 'User not found' });
        assertUsableStatus(user);

        const claims = await resolveClaims(state, user, { isNewUser: false, method: 'webauthn' });
        const session = await issueSession(state, { user, claims, req });

        await auditLog(state.logger, state.hooks, 'WEBAUTHN_LOGIN', { userId: String(user.id), credentialId: credentialDoc.credentialId });

        setSessionCookies(res, state, session);
        res.json({
            accessToken: session.accessToken.token,
            accessTokenExpiresAt: session.accessToken.expiresAt,
            refreshToken: session.refreshTokenValue,
            refreshTokenExpiresAt: session.refreshExpiresAt,
            userId: String(user.id),
        });
    } catch (err) {
        next(err);
    }
}
