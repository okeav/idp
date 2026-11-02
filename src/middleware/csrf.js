import { IdpError } from '../errors/idp-error.js';

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

/**
 * CSRF defence for requests whose credential is a COOKIE (session cookie, refresh cookie). A cookie
 * is attached by the browser whoever builds the request; SameSite=Lax keeps it off cross-SITE
 * POSTs, but not off requests from a sibling subdomain (same site, different origin), and not at
 * all under `cookies.sameSite: 'none'`. So a state-changing cookie request must also come from a
 * trusted origin:
 *
 * - `Sec-Fetch-Site: same-origin` → allowed;
 * - an `Origin` header → it must be the issuer's origin or one of `config.cookies.trustedOrigins`
 *   (your frontends' origins);
 * - neither header → not a browser (browsers send `Origin` on every cross-origin unsafe request) →
 *   allowed.
 *
 * Requests authenticated by an `Authorization: Bearer` header are not affected: a browser never
 * attaches that on its own.
 */
export function assertTrustedOrigin(state, req) {
    if (SAFE_METHODS.has(String(req.method).toUpperCase())) return;
    const fetchSite = req.headers['sec-fetch-site'];
    if (fetchSite === 'same-origin') return;

    const origin = req.headers.origin;
    if (origin !== undefined) {
        if (trustedOrigins(state).has(origin)) return;
        throw CSRF_REJECTED();
    }
    if (fetchSite !== undefined && fetchSite !== 'none') throw CSRF_REJECTED();
}

function trustedOrigins(state) {
    const set = new Set(state.config.cookies?.trustedOrigins || []);
    try {
        set.add(new URL(state.config.issuer).origin);
    } catch {
        // an issuer that isn't a URL contributes no origin
    }
    return set;
}

const CSRF_REJECTED = () => new IdpError({
    code: 'CSRF_ORIGIN_REJECTED',
    httpStatus: 403,
    message: 'Cross-origin request refused — add your frontend origin to config.cookies.trustedOrigins',
});
