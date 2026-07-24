import { generateRegistrationOptions, verifyRegistrationResponse } from '@simplewebauthn/server';
import { getState } from '../config/state.js';
import { IdpError } from '../errors/idp-error.js';
import { getWebauthnConfig } from './config.js';
import { storeChallenge, consumeChallenge } from './challenge-store.js';
import { auditLog } from '../hooks/index.js';

/**
 * POST /webauthn/registration/options
 *
 * Always requires an authenticated caller — a passkey is added to an
 * already-established account (via password, magic link, SSO, ...), the
 * same way every serious WebAuthn implementation works. There is no
 * "register a passkey for a brand-new anonymous user" ceremony in this
 * package; combine a magic-link signup with an immediate call here if you
 * want that UX (see README).
 */
export async function generateRegistrationOptionsHandler(req, res, next) {
    try {
        const state = getState();
        if (!req.auth?.userId) throw new IdpError({ code: 'UNAUTHENTICATED', httpStatus: 401, message: 'Authentication required' });
        const { rpID, rpName } = getWebauthnConfig(state);

        const user = await state.storage.userRepository.findById(req.auth.userId);
        if (!user) throw new IdpError({ code: 'USER_NOT_FOUND', httpStatus: 404, message: 'User not found' });

        const existingCredentials = await state.storage.credentialRepository.findByUserId(user.id);

        const options = await generateRegistrationOptions({
            rpName,
            rpID,
            userName: user.email,
            userDisplayName: user.profile?.displayName || user.email,
            userID: new TextEncoder().encode(String(user.id)),
            attestationType: 'none',
            excludeCredentials: existingCredentials.map((c) => ({ id: c.credentialId, transports: c.transports })),
            authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' },
        });

        await storeChallenge(state, `reg:${user.id}`, options.challenge);

        res.json(options);
    } catch (err) {
        next(err);
    }
}

/** POST /webauthn/registration/verify */
export async function verifyRegistrationHandler(req, res, next) {
    try {
        const state = getState();
        if (!req.auth?.userId) throw new IdpError({ code: 'UNAUTHENTICATED', httpStatus: 401, message: 'Authentication required' });
        const { rpID, origin } = getWebauthnConfig(state);

        const expectedChallenge = await consumeChallenge(state, `reg:${req.auth.userId}`);
        if (!expectedChallenge) {
            throw new IdpError({ code: 'WEBAUTHN_CHALLENGE_EXPIRED', httpStatus: 400, message: 'Registration challenge expired or not found — restart registration' });
        }

        const { response, name } = req.body;

        let result;
        try {
            result = await verifyRegistrationResponse({ response, expectedChallenge, expectedOrigin: origin, expectedRPID: rpID });
        } catch (cause) {
            throw new IdpError({ code: 'WEBAUTHN_VERIFICATION_FAILED', httpStatus: 400, message: 'WebAuthn registration verification failed', cause });
        }
        if (!result.verified) {
            throw new IdpError({ code: 'WEBAUTHN_VERIFICATION_FAILED', httpStatus: 400, message: 'WebAuthn registration verification failed' });
        }

        const { credential, credentialDeviceType, credentialBackedUp } = result.registrationInfo;

        const saved = await state.storage.credentialRepository.create({
            userId: req.auth.userId,
            credentialId: credential.id,
            publicKey: Buffer.from(credential.publicKey).toString('base64'),
            counter: credential.counter,
            transports: credential.transports || [],
            deviceType: credentialDeviceType,
            backedUp: credentialBackedUp,
            name: name || null,
        });

        await auditLog(state.logger, state.hooks, 'WEBAUTHN_CREDENTIAL_REGISTERED', { userId: req.auth.userId, credentialId: credential.id });

        res.status(201).json({ id: saved.id, credentialId: saved.credentialId, deviceType: saved.deviceType, backedUp: saved.backedUp, name: saved.name });
    } catch (err) {
        next(err);
    }
}
