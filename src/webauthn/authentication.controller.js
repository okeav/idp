import crypto from 'crypto';
import { generateAuthenticationOptions } from '@simplewebauthn/server';
import { getState } from '../config/state.js';
import { IdpError } from '../errors/idp-error.js';
import { getWebauthnConfig } from './config.js';
import { storeChallenge, consumeChallenge } from './challenge-store.js';
import { auditLog } from '../hooks/index.js';
import { verifyStoredCredentialAssertion } from './shared.js';
import { issueSession, setSessionCookies, resolveClaims, assertUsableStatus, refreshTokenInBody } from '../password-auth/controllers.js';
import { enforceRateLimit } from '../rate-limit/enforce.js';
import { ipKey } from '../rate-limit/keys.js';

/**
 * Primary/passwordless login — no prior session or password required. This
 * is a genuinely different starting point than the MFA-second-factor flow
 * (src/webauthn/mfa.controller.js): here, WHICH user is authenticating is
 * established entirely by the credential ID in the assertion response
 * (globally unique per the WebAuthn spec) — there's no `mfaChallengeToken`
 * or prior password check identifying them first.
 *
 * Because the passkey alone logs the user in, user verification (PIN /
 * biometric) is REQUIRED: possession plus verification is what makes a
 * passkey login multi-factor. An assertion without the UV flag is refused.
 *
 * The pending challenge has no natural "known user" key to store it under
 * for a usernameless ceremony, so it's keyed by the challenge value itself
 * (decoded back out of the assertion response at verify time).
 */
function decodeChallengeFromResponse(response) {
    try {
        const clientDataJSON = JSON.parse(Buffer.from(response.response.clientDataJSON, 'base64url').toString('utf8'));
        return typeof clientDataJSON.challenge === 'string' ? clientDataJSON.challenge : null;
    } catch {
        return null;
    }
}

const VERIFICATION_FAILED = (message = 'WebAuthn assertion verification failed') => new IdpError({ code: 'WEBAUTHN_VERIFICATION_FAILED', httpStatus: 400, message });

/**
 * POST /webauthn/authentication/options
 *
 * By default this always answers a usernameless/discoverable-credential challenge (the browser
 * lets the user pick a passkey) and ignores `email`: listing an account's credential ids for an
 * email tells anyone who asks whether that address has an account with passkeys. Set
 * `config.webauthn.allowCredentialsByEmail: true` to scope the challenge to the email's
 * credentials (needed only for non-discoverable credentials); unknown addresses then get a stable
 * decoy id, so they look like an account with one passkey.
 */
export async function generateAuthenticationOptionsHandler(req, res, next) {
    try {
        const state = getState();
        await enforceRateLimit(state, `webauthn-authn:ip:${ipKey(req.ip)}`, state.config.rateLimiting.webauthnAuthentication, { failMode: 'closed' });
        const { rpID } = getWebauthnConfig(state);
        const { email } = req.body || {};

        let allowCredentials;
        if (email && state.config.webauthn?.allowCredentialsByEmail === true) {
            const user = await state.storage.userRepository.findByEmail(email);
            const credentials = user ? await state.storage.credentialRepository.findByUserId(user.id) : [];
            // No transports: they'd distinguish real credentials from the decoy.
            allowCredentials = credentials.length > 0
                ? credentials.map((c) => ({ id: c.credentialId }))
                : [{ id: decoyCredentialId(state, email) }];
        }

        const options = await generateAuthenticationOptions({ rpID, allowCredentials, userVerification: 'required' });

        await storeChallenge(state, `authn:${options.challenge}`, true);

        res.json(options);
    } catch (err) {
        next(err);
    }
}

function decoyCredentialId(state, email) {
    return crypto.createHmac('sha256', state.config.security.tokenHashSecret).update(`webauthn-decoy:${state.normalizeEmail(email)}`).digest('base64url');
}

/** POST /webauthn/authentication/verify — issues a full session through the same resolveAuthContext + issueSession path every other login method uses. */
export async function verifyAuthenticationHandler(req, res, next) {
    try {
        const state = getState();
        await enforceRateLimit(state, `webauthn-authn:ip:${ipKey(req.ip)}`, state.config.rateLimiting.webauthnAuthentication, { failMode: 'closed' });
        const { response } = req.body;

        const challenge = decodeChallengeFromResponse(response);
        if (!challenge) throw new IdpError({ code: 'INVALID_REQUEST', httpStatus: 400, message: 'Malformed WebAuthn assertion response' });

        const consumed = await consumeChallenge(state, `authn:${challenge}`);
        if (!consumed) throw new IdpError({ code: 'WEBAUTHN_CHALLENGE_EXPIRED', httpStatus: 400, message: 'Authentication challenge expired or not found — restart login' });

        const credentialDoc = await verifyStoredCredentialAssertion(state, { response, expectedChallenge: challenge, requireUserVerification: true });

        // A discoverable credential reports the user handle it was registered with (our user id). It
        // must name the credential's owner — never trust one without the other.
        const userHandle = response.response?.userHandle;
        if (userHandle && Buffer.from(String(userHandle), 'base64url').toString('utf8') !== String(credentialDoc.user)) {
            throw VERIFICATION_FAILED('Credential user handle does not match its owner');
        }

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
            ...refreshTokenInBody(state, session.refreshTokenValue),
            refreshTokenExpiresAt: session.refreshExpiresAt,
            userId: String(user.id),
        });
    } catch (err) {
        next(err);
    }
}
