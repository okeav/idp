import { isKeyPublishable, DEFAULT_ROTATION_GRACE_SECONDS } from './key-status.js';

/** In-process key lookup — used when the verifier is the IDP itself, which has direct storage access. */
export function localKeyLookup(serviceKeyRepository, { rotationGraceSeconds = DEFAULT_ROTATION_GRACE_SECONDS } = {}) {
    return async (kid) => {
        const match = typeof serviceKeyRepository.findPublishableByKid === 'function'
            ? await serviceKeyRepository.findPublishableByKid(kid)
            : (await serviceKeyRepository.listPublishable()).find((k) => k.kid === kid);
        if (!match || !isKeyPublishable(match, rotationGraceSeconds)) return null;
        return { publicKeyPem: Buffer.from(match.publicKey, 'base64').toString('utf8'), service: match.name };
    };
}
