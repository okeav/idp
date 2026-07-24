import crypto from 'crypto';
import { getState } from '../config/state.js';
import { IdpError } from '../errors/idp-error.js';
import { deriveKid } from './verify-service-token.js';
import { auditLog } from '../hooks/index.js';

/**
 * POST /internal/service-keys — a service publishes its S2S public key.
 * Idempotent by (name, publicKey) → kid. Gate with `s2sBootstrapMiddleware`.
 */
export async function registerServiceKeyHandler(req, res, next) {
    try {
        const state = getState();
        const { name, publicKey: publicKeyB64, region } = req.body ?? {};

        if (!name || typeof name !== 'string') {
            throw new IdpError({ code: 'INVALID_REQUEST', httpStatus: 400, message: 'name is required' });
        }
        if (!publicKeyB64 || typeof publicKeyB64 !== 'string') {
            throw new IdpError({ code: 'INVALID_REQUEST', httpStatus: 400, message: 'publicKey (base64 PEM) is required' });
        }

        let publicKeyPem;
        try {
            publicKeyPem = Buffer.from(publicKeyB64, 'base64').toString('utf8');
            crypto.createPublicKey(publicKeyPem);
        } catch (err) {
            throw new IdpError({ code: 'INVALID_REQUEST', httpStatus: 400, message: `Invalid public key: ${err.message}` });
        }

        const kid = deriveKid(name, publicKeyPem);
        const saved = await state.storage.serviceKeyRepository.upsertByKid({ kid, name, publicKey: publicKeyB64, region });

        await auditLog(state.logger, state.hooks, 'SERVICE_KEY_REGISTERED', { name, kid: saved.kid });
        res.status(201).json({ kid: saved.kid, name: saved.name });
    } catch (err) {
        next(err);
    }
}

/**
 * GET /.well-known/services-jwks.json — union JWKS for every ACTIVE/ROTATING
 * service key. Public — keys are public by definition, no auth required.
 */
export async function getServicesJwksHandler(req, res, next) {
    try {
        const state = getState();
        const docs = await state.storage.serviceKeyRepository.listPublishable();
        const keys = docs.map((doc) => {
            const pem = Buffer.from(doc.publicKey, 'base64').toString('utf8');
            const jwk = crypto.createPublicKey(pem).export({ format: 'jwk' });
            return { ...jwk, use: 'sig', alg: 'RS256', kid: doc.kid, service: doc.name, status: doc.status };
        });
        res.set('Cache-Control', 'public, max-age=60');
        res.json({ keys });
    } catch (err) {
        next(err);
    }
}
