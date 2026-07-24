import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { IdpError } from '../errors/idp-error.js';

/**
 * Core S2S-JWT verification, parameterized over a `lookupKey(kid)` function
 * so it works both for the IDP verifying inbound calls against its own
 * in-process ServiceKeyRepository, and for a downstream service verifying
 * against a remote JWKS fetched over HTTP (see remote-jwks-key-lookup.js).
 *
 * @param {string} token
 * @param {{ expectedAud: string, expectedIss?: string }} opts
 * @param {(kid: string, opts: {forceRefresh?: boolean}) => Promise<{publicKeyPem: string, service?: string}|null>} lookupKey
 */
export async function verifyServiceTokenWith(token, opts, lookupKey) {
    const { expectedAud, expectedIss } = opts;
    if (!token) throw badToken('Missing service token');
    if (!expectedAud) throw new Error('verifyServiceToken: expectedAud is required');

    const decoded = jwt.decode(token, { complete: true });
    if (!decoded?.header?.kid) throw badToken('Service token missing kid');

    let entry = await lookupKey(decoded.header.kid, {});
    if (!entry) entry = await lookupKey(decoded.header.kid, { forceRefresh: true }); // peer may have just rotated
    if (!entry) throw badToken(`Unknown service key kid: ${decoded.header.kid}`);

    let payload;
    try {
        payload = jwt.verify(token, entry.publicKeyPem, {
            algorithms: ['RS256'],
            audience: expectedAud,
            clockTolerance: 30,
            ...(expectedIss ? { issuer: expectedIss } : {}),
        });
    } catch (err) {
        if (err?.name === 'TokenExpiredError') {
            throw new IdpError({ code: 'TOKEN_EXPIRED', httpStatus: 401, message: 'Service token expired' });
        }
        throw badToken(err.message);
    }

    if (entry.service && payload.iss !== entry.service) {
        throw badToken(`Service token iss=${payload.iss} doesn't match key owner ${entry.service}`);
    }

    return payload;
}

function badToken(message) {
    return new IdpError({ code: 'SERVICE_TOKEN_INVALID', httpStatus: 401, message });
}

export function deriveKid(serviceName, publicKeyPem) {
    const jwk = crypto.createPublicKey(publicKeyPem).export({ format: 'jwk' });
    const canonical = JSON.stringify({ e: jwk.e, kty: jwk.kty, n: jwk.n });
    const digest = crypto.createHash('sha256').update(canonical).digest('hex');
    return `${serviceName}:${digest.slice(0, 16)}`;
}
