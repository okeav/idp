import crypto from 'crypto';
import { getState } from '../config/state.js';
import { IdpError } from '../errors/idp-error.js';
import { KEY_STATUS } from '../config/constants.js';
import { deriveKid } from './verify-service-token.js';
import { auditLog } from '../hooks/index.js';
import { isKeyPublishable } from './key-status.js';

export const SERVICE_NAME_PATTERN = /^[a-z0-9][a-z0-9-]{0,62}$/;
const MIN_RSA_BITS = 2048;

const invalid = (message) => new IdpError({ code: 'INVALID_REQUEST', httpStatus: 400, message });

/**
 * Parses a registration's public key. Only an RSA PUBLIC key of at least 2048 bits: tokens are
 * verified as RS256, a weak key can be factored, and a private key PEM (which `createPublicKey`
 * happily accepts) must never be stored or served. Returns the normalized SPKI PEM.
 */
function parsePublicKey(publicKeyB64) {
    let pem;
    try {
        pem = Buffer.from(publicKeyB64, 'base64').toString('utf8');
    } catch {
        throw invalid('publicKey must be a base64-encoded PEM');
    }
    let isPrivate = false;
    try {
        crypto.createPrivateKey(pem);
        isPrivate = true;
    } catch {
        // not a private key — expected
    }
    if (isPrivate) throw invalid('publicKey is a PRIVATE key — send only the public key (and rotate this one: it has left the service)');

    let key;
    try {
        key = crypto.createPublicKey(pem);
    } catch {
        throw invalid('publicKey is not a valid public key PEM');
    }
    if (key.asymmetricKeyType !== 'rsa') throw invalid('publicKey must be an RSA key (tokens are RS256)');
    if ((key.asymmetricKeyDetails?.modulusLength ?? 0) < MIN_RSA_BITS) throw invalid(`publicKey must be at least ${MIN_RSA_BITS} bits`);
    return key.export({ format: 'pem', type: 'spki' }).toString('utf8');
}

/**
 * POST /internal/service-keys — a service publishes its S2S public key. Gate with
 * `s2sBootstrapMiddleware`.
 *
 * - Re-registering the same key (same kid) is idempotent.
 * - A per-service bootstrap secret (`serviceMesh.bootstrapSecrets`) authorizes exactly its own name,
 *   and may register a new key for it (rotation): the previous keys move to ROTATING (still
 *   verifiable, so in-flight tokens keep working) and are retired on the next rotation.
 * - The shared `serviceMesh.bootstrapSecret` may only register a name that has no live key, and never
 *   a name that has its own per-service secret: it proves "some participating service", not which
 *   one, so it must not be able to replace another service's key and impersonate it. (A shared-secret
 *   name whose keys were all revoked can be registered again by a shared-secret holder — that is how
 *   such a service recovers; give a service its own secret to rule that out.)
 * - A revoked key is never accepted again (409 SERVICE_KEY_REVOKED): the service must generate a new one.
 * - A rotated-away (ROTATING) key keeps verifying for `serviceMesh.rotationGraceSeconds` only.
 * - `serviceMesh.allowedServiceNames`, when set, limits which names can register at all.
 */
export async function registerServiceKeyHandler(req, res, next) {
    try {
        const state = getState();
        const { name, publicKey: publicKeyB64, region } = req.body ?? {};

        if (typeof name !== 'string' || !SERVICE_NAME_PATTERN.test(name)) throw invalid('name must match /^[a-z0-9][a-z0-9-]{0,62}$/');
        if (region !== undefined && (typeof region !== 'string' || !/^[A-Za-z0-9_-]{1,32}$/.test(region))) throw invalid('region must be 1-32 characters [A-Za-z0-9_-]');
        if (!publicKeyB64 || typeof publicKeyB64 !== 'string' || publicKeyB64.length > 8192) throw invalid('publicKey (base64 PEM) is required');

        const allowedNames = state.config.serviceMesh?.allowedServiceNames;
        if (Array.isArray(allowedNames) && !allowedNames.includes(name)) {
            throw new IdpError({ code: 'FORBIDDEN', httpStatus: 403, message: `Service name '${name}' is not allowed to register` });
        }
        const auth = req.s2sBootstrap;
        if (!auth || (!auth.shared && auth.serviceName !== name)) {
            throw new IdpError({ code: 'UNAUTHENTICATED', httpStatus: 401, message: 'Bootstrap credential does not cover this service name' });
        }
        const perService = state.config.serviceMesh?.bootstrapSecrets;
        if (auth.shared && perService && Object.hasOwn(perService, name)) {
            await auditLog(state.logger, state.hooks, 'SERVICE_KEY_REGISTRATION_REFUSED', { name, reason: 'name_has_own_secret' });
            throw new IdpError({ code: 'FORBIDDEN', httpStatus: 403, message: `Service '${name}' registers with its own bootstrap secret, not the shared one` });
        }

        const publicKeyPem = parsePublicKey(publicKeyB64);
        const kid = deriveKid(name, publicKeyPem);
        const repo = state.storage.serviceKeyRepository;
        const revoked = () => new IdpError({ code: 'SERVICE_KEY_REVOKED', httpStatus: 409, message: 'This key was revoked — generate a new key pair' });
        // Checked before a rotation demotes the current key (upsertByKid refuses it again, atomically).
        if (typeof repo.findByKid === 'function' && (await repo.findByKid(kid))?.status === KEY_STATUS.REVOKED) {
            await auditLog(state.logger, state.hooks, 'SERVICE_KEY_REGISTRATION_REFUSED', { name, kid, reason: 'key_revoked' });
            throw revoked();
        }
        const existing = (await repo.listPublishable()).filter((k) => k.name === name);
        const sameKey = existing.some((k) => k.kid === kid);

        const nameTaken = async () => {
            await auditLog(state.logger, state.hooks, 'SERVICE_KEY_REGISTRATION_REFUSED', { name, kid, reason: 'name_taken' });
            return new IdpError({ code: 'SERVICE_NAME_TAKEN', httpStatus: 409, message: `Service '${name}' already has a key; rotating it needs that service's own bootstrap secret` });
        };
        if (existing.length > 0 && !sameKey && auth.shared) throw await nameTaken();

        // The new key goes in first: a registration refused here (a revoked kid) must not have demoted
        // the service's current key already.
        const saved = await repo.upsertByKid({ kid, name, publicKey: Buffer.from(publicKeyPem, 'utf8').toString('base64'), region });
        if (!saved) throw revoked();

        if (existing.length > 0 && !sameKey) {
            // Per-service rotation: retire keys already rotating, demote the active ones — each only from
            // the status just read, so a key revoked meanwhile stays revoked.
            for (const k of existing) {
                await repo.setStatusByKid(k.kid, k.status === KEY_STATUS.ROTATING ? KEY_STATUS.RETIRED : KEY_STATUS.ROTATING, { expectedStatus: k.status });
            }
        }
        if (auth.shared && existing.length === 0) {
            // Concurrent first registrations of one new name with the shared secret all saw "no key yet".
            // Exactly one keeps it — the earliest registered (then lowest kid); the others revoke their own.
            const rivals = (await repo.listPublishable()).filter((k) => k.name === name && k.status === KEY_STATUS.ACTIVE);
            const winner = rivals.sort((a, b) => (new Date(a.registeredAt) - new Date(b.registeredAt)) || String(a.kid).localeCompare(String(b.kid)))[0];
            if (winner && winner.kid !== kid) {
                await repo.setStatusByKid(kid, KEY_STATUS.REVOKED);
                throw await nameTaken();
            }
        }

        await auditLog(state.logger, state.hooks, 'SERVICE_KEY_REGISTERED', { name, kid: saved.kid, rotated: existing.length > 0 && !sameKey });
        res.status(201).json({ kid: saved.kid, name: saved.name });
    } catch (err) {
        next(err);
    }
}

/**
 * Revokes a service key by kid (programmatic, for your admin tooling): it is no longer published or
 * accepted. The name can then be registered again with a new key.
 */
export async function revokeServiceKey(kid) {
    const state = getState();
    const updated = await state.storage.serviceKeyRepository.setStatusByKid(kid, KEY_STATUS.REVOKED);
    if (updated) await auditLog(state.logger, state.hooks, 'SERVICE_KEY_REVOKED', { kid });
    return Boolean(updated);
}

/**
 * GET /.well-known/services-jwks.json — union JWKS for every ACTIVE/ROTATING
 * service key. Public — keys are public by definition, no auth required.
 */
export async function getServicesJwksHandler(req, res, next) {
    try {
        const state = getState();
        const docs = await state.storage.serviceKeyRepository.listPublishable();
        const grace = state.config.serviceMesh?.rotationGraceSeconds;
        const keys = [];
        for (const doc of docs.filter((d) => isKeyPublishable(d, grace))) {
            try {
                const key = crypto.createPublicKey(Buffer.from(doc.publicKey, 'base64').toString('utf8'));
                // Never publish anything but an RSA public key (rows written before 0.4.0 weren't validated).
                if (key.asymmetricKeyType !== 'rsa') continue;
                keys.push({ ...key.export({ format: 'jwk' }), use: 'sig', alg: 'RS256', kid: doc.kid, service: doc.name, status: doc.status });
            } catch {
                state.logger?.warn?.({ kid: doc.kid }, 'Skipping an unreadable service key');
            }
        }
        res.set('Cache-Control', 'public, max-age=60');
        res.json({ keys });
    } catch (err) {
        next(err);
    }
}
