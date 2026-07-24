import { getState } from '../config/state.js';
import { IdpError } from '../errors/idp-error.js';

/**
 * Bootstrap-secret gate for `registerServiceKeyHandler`. Solves the
 * chicken-and-egg problem: a service can't mint an S2S JWT before its key is
 * registered, so registration itself can't be gated on an S2S JWT. Every
 * participating service is configured with the same
 * `config.serviceMesh.bootstrapSecret` and presents it once via the
 * `x-s2s-bootstrap-secret` header.
 */
export function s2sBootstrapMiddleware(req, _res, next) {
    const state = getState();
    const expected = state.config.serviceMesh?.bootstrapSecret;
    const presented = req.headers['x-s2s-bootstrap-secret'];

    if (!expected || !presented || presented !== expected) {
        return next(new IdpError({ code: 'UNAUTHENTICATED', httpStatus: 401, message: 'Invalid bootstrap secret' }));
    }
    next();
}
