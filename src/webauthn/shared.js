import { verifyAuthenticationResponse } from '@simplewebauthn/server';
import { IdpError } from '../errors/idp-error.js';
import { getWebauthnConfig } from './config.js';

/**
 * Looks up the stored credential for an incoming assertion response,
 * reconstructs it into the shape `@simplewebauthn/server` expects, verifies
 * the assertion (which itself enforces the signature-counter-must-increase
 * replay check), and persists the new counter on success.
 *
 * Shared by both the primary-passwordless-login and MFA-second-factor
 * verify handlers — everything about *establishing who's authenticating*
 * differs between those two (see their respective controllers), but the
 * cryptographic verify-and-update-counter step is identical either way.
 *
 * @returns the stored credential document (with its `user` field) on success
 * @throws {IdpError} CREDENTIAL_NOT_FOUND | WEBAUTHN_VERIFICATION_FAILED
 */
export async function verifyStoredCredentialAssertion(state, { response, expectedChallenge }) {
    const { rpID, origin } = getWebauthnConfig(state);

    const credentialId = response?.id;
    if (!credentialId) throw new IdpError({ code: 'INVALID_REQUEST', httpStatus: 400, message: 'Malformed WebAuthn assertion response' });

    const stored = await state.storage.credentialRepository.findByCredentialId(credentialId);
    if (!stored) throw new IdpError({ code: 'CREDENTIAL_NOT_FOUND', httpStatus: 400, message: 'Unknown credential' });

    const webAuthnCredential = {
        id: stored.credentialId,
        publicKey: Buffer.from(stored.publicKey, 'base64'),
        counter: stored.counter,
        transports: stored.transports,
    };

    let result;
    try {
        result = await verifyAuthenticationResponse({
            response,
            expectedChallenge,
            expectedOrigin: origin,
            expectedRPID: rpID,
            credential: webAuthnCredential,
        });
    } catch (cause) {
        throw new IdpError({ code: 'WEBAUTHN_VERIFICATION_FAILED', httpStatus: 400, message: 'WebAuthn assertion verification failed', cause });
    }

    if (!result.verified) {
        throw new IdpError({ code: 'WEBAUTHN_VERIFICATION_FAILED', httpStatus: 400, message: 'WebAuthn assertion verification failed' });
    }

    await state.storage.credentialRepository.updateCounter(stored.credentialId, result.authenticationInfo.newCounter);

    return stored;
}
