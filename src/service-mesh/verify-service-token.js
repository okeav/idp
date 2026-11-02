import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { IdpError } from '../errors/idp-error.js';

// Service tokens are minted per call with a 60 s lifetime (see service-identity.client.js). Anything
// claiming to live longer — or with no expiry at all — wasn't minted by a well-behaved peer, and a
// token that never expires can't be cut off by revoking its key's future signatures.
export const SERVICE_TOKEN_MAX_AGE_SECONDS = 5 * 60;
const CLOCK_TOLERANCE_SECONDS = 30;

/**
 * Core S2S-JWT verification, parameterized over a `lookupKey(kid)` function
 * so it works both for the IDP verifying inbound calls against its own
 * in-process ServiceKeyRepository, and for a downstream service verifying
 * against a remote JWKS fetched over HTTP (see remote-jwks-key-lookup.js).
 *
 * Requires RS256, `aud` = the expected service, `exp` and `iat` (issued no more than
 * SERVICE_TOKEN_MAX_AGE_SECONDS ago and not in the future), and `iss` = the key's owner.
 *
 * @param {string} token
 * @param {{ expectedAud: string, expectedIss?: string }} opts
 * @param {(kid: string, opts: {forceRefresh?: boolean}) => Promise<{publicKeyPem: string, service?: string}|null>} lookupKey
 */
export async function verifyServiceTokenWith(token, opts, lookupKey) {
    const { expectedAud, expectedIss } = opts;
    if (!expectedAud) {
        throw new IdpError({ code: 'SERVICE_NOT_CONFIGURED', httpStatus: 500, message: 'verifyServiceToken: expectedAud (this service\'s own name) is required' });
    }
    if (!token) throw badToken('Missing service token');

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
            clockTolerance: CLOCK_TOLERANCE_SECONDS,
            maxAge: SERVICE_TOKEN_MAX_AGE_SECONDS,
            ...(expectedIss ? { issuer: expectedIss } : {}),
        });
    } catch (err) {
        if (err?.name === 'TokenExpiredError') {
            throw new IdpError({ code: 'TOKEN_EXPIRED', httpStatus: 401, message: 'Service token expired' });
        }
        throw badToken(err.message);
    }

    const now = Math.floor(Date.now() / 1000);
    if (typeof payload.exp !== 'number') throw badToken('Service token has no expiry');
    if (typeof payload.iat !== 'number' || payload.iat > now + CLOCK_TOLERANCE_SECONDS) throw badToken('Service token iat is missing or in the future');
    if (payload.exp - payload.iat > SERVICE_TOKEN_MAX_AGE_SECONDS) throw badToken('Service token lifetime is too long');

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
