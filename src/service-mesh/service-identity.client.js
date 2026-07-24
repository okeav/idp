import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import { deriveKid, verifyServiceTokenWith } from './verify-service-token.js';
import { remoteJwksKeyLookup } from './remote-jwks-key-lookup.js';

const TOKEN_TTL_SECONDS = 60;

let _identity = { serviceName: null, region: 'global', kid: null, privateKeyPem: null, publicKeyPem: null };
let _remoteLookup = null;

/**
 * Registers this process's own S2S keypair with an IDP instance (this one,
 * or a separately-deployed one) so other services can verify tokens it
 * mints. Call once at startup. Idempotent — re-running with the same key is
 * a no-op server-side (upsert by kid).
 *
 * @param {{ serviceName: string, privateKeyPem: string, region?: string, idpBaseUrl: string, bootstrapSecret: string }} opts
 */
export async function initServiceIdentity(opts = {}) {
    const { serviceName, privateKeyPem, region = 'global', idpBaseUrl, bootstrapSecret } = opts;
    if (!serviceName) throw new Error('initServiceIdentity: serviceName is required');
    if (!privateKeyPem) throw new Error('initServiceIdentity: privateKeyPem is required');
    if (!idpBaseUrl) throw new Error('initServiceIdentity: idpBaseUrl is required');
    if (!bootstrapSecret) throw new Error('initServiceIdentity: bootstrapSecret is required');

    const publicKeyPem = crypto.createPublicKey(privateKeyPem).export({ format: 'pem', type: 'spki' }).toString('utf8');
    const kid = deriveKid(serviceName, publicKeyPem);

    _identity = { serviceName, region, kid, privateKeyPem, publicKeyPem };
    _remoteLookup = remoteJwksKeyLookup(idpBaseUrl);

    const registerUrl = `${idpBaseUrl.replace(/\/$/, '')}/internal/service-keys`;
    const res = await fetch(registerUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-s2s-bootstrap-secret': bootstrapSecret },
        body: JSON.stringify({ name: serviceName, publicKey: Buffer.from(publicKeyPem, 'utf8').toString('base64'), region }),
    });
    if (!res.ok) {
        const body = await res.text().catch(() => '');
        throw new Error(`Failed to register service key with IDP (${res.status}): ${body}`);
    }

    return { kid };
}

export function getServiceIdentity() {
    if (!_identity.kid) throw new Error('Service identity not initialized — call initServiceIdentity() at startup');
    return { serviceName: _identity.serviceName, kid: _identity.kid, region: _identity.region };
}

export function mintServiceToken(targetService, { scopes = [] } = {}) {
    if (!_identity.privateKeyPem) throw new Error('mintServiceToken: identity not initialized — call initServiceIdentity() first');
    if (!targetService) throw new Error('mintServiceToken: targetService is required');

    const now = Math.floor(Date.now() / 1000);
    const payload = {
        iss: _identity.serviceName,
        aud: targetService,
        iat: now,
        exp: now + TOKEN_TTL_SECONDS,
        jti: crypto.randomUUID(),
        region: _identity.region,
        ...(scopes.length ? { scope: scopes.join(' ') } : {}),
    };

    return jwt.sign(payload, _identity.privateKeyPem, { algorithm: 'RS256', keyid: _identity.kid });
}

/**
 * Verifies an inbound S2S JWT against a remote IDP's public services-JWKS
 * endpoint. Use this in a downstream service that does NOT itself run
 * `@okeav/idp-core` — a service that does should use
 * `serviceContextMiddleware` instead, which looks keys up in-process.
 */
export async function verifyServiceTokenRemote(token, { expectedAud, expectedIss, idpBaseUrl } = {}) {
    const lookup = idpBaseUrl ? remoteJwksKeyLookup(idpBaseUrl) : _remoteLookup;
    if (!lookup) throw new Error('verifyServiceTokenRemote: pass idpBaseUrl, or call initServiceIdentity() first');
    return verifyServiceTokenWith(token, { expectedAud, expectedIss }, lookup);
}
