import { getState } from '../config/state.js';
import { IdpError } from '../errors/idp-error.js';
import { safeEqualSecret } from '../utils/safe-equal.js';
import { enforceRateLimit } from '../rate-limit/enforce.js';

/**
 * Bootstrap gate for `registerServiceKeyHandler`. A service can't mint an S2S JWT before its key is
 * registered, so registration is gated on a bootstrap secret in the `x-s2s-bootstrap-secret` header.
 *
 * Preferred: `config.serviceMesh.bootstrapSecrets = { <serviceName>: <secret> }` — one credential per
 * service, so the secret proves WHICH service is registering (`req.s2sBootstrap.serviceName`). The
 * single shared `config.serviceMesh.bootstrapSecret` is still accepted, but proves only "some
 * participating service": the handler then refuses to change the key of a name that already has one.
 */
export async function s2sBootstrapMiddleware(req, _res, next) {
    try {
        const state = getState();
        await enforceRateLimit(state, `s2s-bootstrap:ip:${req.ip}`, state.config.rateLimiting.serviceKeyRegistration, { failMode: 'closed' });

        const presented = req.headers['x-s2s-bootstrap-secret'];
        const name = req.body?.name;
        const perService = state.config.serviceMesh?.bootstrapSecrets;
        const shared = state.config.serviceMesh?.bootstrapSecret;
        const DENIED = () => new IdpError({ code: 'UNAUTHENTICATED', httpStatus: 401, message: 'Invalid bootstrap secret' });

        if (typeof presented !== 'string' || presented.length === 0) return next(DENIED());

        if (perService && typeof name === 'string' && Object.hasOwn(perService, name) && safeEqualSecret(presented, perService[name])) {
            req.s2sBootstrap = { serviceName: name, shared: false };
            return next();
        }
        if (shared && safeEqualSecret(presented, shared)) {
            req.s2sBootstrap = { serviceName: null, shared: true };
            return next();
        }
        next(DENIED());
    } catch (err) {
        next(err);
    }
}
