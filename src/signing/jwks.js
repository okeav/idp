import crypto from 'crypto';
import { getVerifiableKeys } from './key-registry.js';

/** RFC 7517 JWK Set for this IDP's own user-token signing keys (access/ID/OAuth2 tokens). */
export function buildUserTokenJwks(state) {
    const keys = getVerifiableKeys(state.signingKeys).map(([kid, key]) => {
        const jwk = crypto.createPublicKey(key.publicKeyPem).export({ format: 'jwk' });
        return { ...jwk, use: 'sig', alg: 'RS256', kid };
    });
    return { keys };
}

/** JWK SHA-256 thumbprint per RFC 7638, used to derive stable service kids. */
export function deriveKidFromPublicKey(name, publicKeyPem) {
    const jwk = crypto.createPublicKey(publicKeyPem).export({ format: 'jwk' });
    const canonical = JSON.stringify({ e: jwk.e, kty: jwk.kty, n: jwk.n });
    const digest = crypto.createHash('sha256').update(canonical).digest('hex');
    return `${name}:${digest.slice(0, 16)}`;
}

export function pemToJwk(publicKeyPem, extra = {}) {
    const jwk = crypto.createPublicKey(publicKeyPem).export({ format: 'jwk' });
    return { ...jwk, ...extra };
}
