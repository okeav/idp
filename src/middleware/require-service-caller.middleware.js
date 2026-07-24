import { IdpError } from '../errors/idp-error.js';
import { getState } from '../config/state.js';

/**
 * Pins an internal endpoint to a specific set of upstream services. Runs
 * AFTER `serviceContextMiddleware`. Name-allowlist only — not an RBAC
 * decision, so it stays in scope per the Phase 2 exclusion of scope-catalogue
 * logic.
 */
export function requireServiceCallerMiddleware(...allowedCallers) {
    if (allowedCallers.length === 0) throw new Error('requireServiceCallerMiddleware: at least one allowed caller is required');
    const allowed = new Set(allowedCallers);

    return (req, _res, next) => {
        const caller = req.serviceCaller;
        if (!caller) {
            return next(new IdpError({ code: 'UNAUTHENTICATED', httpStatus: 401, message: 'No authenticated service caller — mount serviceContextMiddleware first' }));
        }
        if (!allowed.has(caller.name)) {
            return next(new IdpError({ code: 'FORBIDDEN', httpStatus: 403, message: `Service '${caller.name}' is not allowed to call this endpoint` }));
        }
        if (caller.source === 'legacy-secret') {
            getState().logger?.warn?.({ caller: caller.name, path: req.originalUrl }, 'Caller identity verified via shared secret, not cryptographically — rely on serviceMesh.tokenMode=token for production');
        }
        next();
    };
}
