import { getState } from '../config/state.js';
import { IdpError } from '../errors/idp-error.js';
import { verifyServiceTokenWith } from '../service-mesh/verify-service-token.js';
import { localKeyLookup } from '../service-mesh/local-key-lookup.js';
import { safeEqualSecret } from '../utils/safe-equal.js';

function parseBearer(header) {
    if (!header || typeof header !== 'string') return null;
    const match = header.match(/^Bearer\s+(.+)$/i);
    return match ? match[1].trim() : null;
}

/**
 * Authenticates an inbound service-to-service request against this IDP's own
 * service-key registry (in-process — no HTTP round trip). Sets
 * `req.serviceCaller = { name, scopes, region, source }`.
 *
 * Mode is `config.serviceMesh.tokenMode` ('token' | 'secret' | 'both',
 * default 'token'). 'secret' and 'both' are a legacy shared-secret fallback for
 * staged rollouts — the caller's claimed name (`x-service-name` header) is NOT
 * verified under it, so `requireServiceCallerMiddleware` refuses such callers
 * unless `serviceMesh.allowLegacySecretCallers` is true.
 *
 * @param {{ ownServiceName: string }} opts - this service's own name (the token `aud` it expects)
 */
export function serviceContextMiddleware(opts = {}) {
    return async function (req, _res, next) {
        const state = getState();
        const mode = state.config.serviceMesh?.tokenMode || 'token';
        const ownName = opts.ownServiceName || state.config.serviceMesh?.ownServiceName;

        try {
            // Without its own name this service can't check a token's audience. That is a configuration
            // error — never a reason to fall back to the shared secret.
            if (!ownName && mode !== 'secret') {
                return next(new IdpError({ code: 'SERVICE_NOT_CONFIGURED', httpStatus: 500, message: 'serviceContextMiddleware: ownServiceName (or config.serviceMesh.ownServiceName) is required' }));
            }
            const bearer = parseBearer(req.headers.authorization);
            const presentedSecret = req.headers['x-internal-service-secret'];

            if (bearer && (mode === 'token' || mode === 'both')) {
                try {
                    const lookup = localKeyLookup(state.storage.serviceKeyRepository);
                    const payload = await verifyServiceTokenWith(bearer, { expectedAud: ownName }, lookup);
                    req.serviceCaller = { name: payload.iss, scopes: payload.scope ? payload.scope.split(' ') : [], region: payload.region, source: 'token' };
                    return next();
                } catch (err) {
                    if (mode === 'token') return next(err);
                    state.logger?.warn?.({ err: err.message }, 'S2S token failed; falling back to legacy secret check (tokenMode=both)');
                }
            }

            if (mode === 'secret' || mode === 'both') {
                const expected = state.config.serviceMesh?.sharedSecret;
                if (!expected) {
                    return next(new IdpError({ code: 'SERVICE_NOT_CONFIGURED', httpStatus: 500, message: 'No serviceMesh.sharedSecret configured and no valid S2S token presented' }));
                }
                if (!safeEqualSecret(presentedSecret, expected)) {
                    return next(new IdpError({ code: 'SERVICE_AUTH_FAILED', httpStatus: 401, message: 'Service authentication failed' }));
                }
                req.serviceCaller = { name: req.headers['x-service-name'] || 'unknown', source: 'legacy-secret' };
                return next();
            }

            return next(new IdpError({ code: 'SERVICE_AUTH_FAILED', httpStatus: 401, message: 'Service authentication failed' }));
        } catch (err) {
            next(err);
        }
    };
}
