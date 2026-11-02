import { IdpError } from '../errors/idp-error.js';

/** Whether cookies are `Secure` (config.cookies.secure; default: everywhere but NODE_ENV=development). */
export function cookiesAreSecure(state) {
    return state.config.cookies?.secure ?? process.env.NODE_ENV !== 'development';
}

/**
 * The real name of a session cookie (`access_token`, `refresh_token`).
 *
 * Cookie tossing: a sibling subdomain (or a script on one) can set a cookie for the parent domain with
 * the same name and a longer path; the browser then sends both, the planted one first, and the server
 * reads the attacker's session — signing the victim into the attacker's account (and an OAuth2 client
 * into the attacker's identity). A `__Host-` cookie can only be set by this exact host, over HTTPS,
 * with Path=/ and no Domain, so it can't be planted. With `cookies.domain` (cookies shared across
 * subdomains by choice) `__Host-` is impossible; `__Secure-` is used and a request carrying the cookie
 * twice is refused (readSessionCookie). Without Secure (development over http) no prefix is allowed.
 */
export function sessionCookieName(state, base) {
    if (!cookiesAreSecure(state)) return base;
    return state.config.cookies?.domain ? `__Secure-${base}` : `__Host-${base}`;
}

/** A host-only cookie name for the IdP's own short-lived cookies (SSO binding): `__Host-` whenever Secure. */
export function hostCookieName(secure, base) {
    return secure ? `__Host-${base}` : base;
}

const COOKIE_CONFLICT = () => new IdpError({
    code: 'COOKIE_CONFLICT',
    httpStatus: 400,
    message: 'Conflicting session cookies — sign in again',
});

/**
 * How many times a cookie name occurs in the raw Cookie header. cookie-parser keeps the first of two
 * same-named cookies, and the browser lists a planted longer-path cookie first — so a duplicate is
 * refused rather than resolved.
 */
function occurrences(req, name) {
    const raw = req.headers?.cookie;
    if (typeof raw !== 'string') return 0;
    // Compared the way the parser reads names — trimmed, up to the first "=" — so a variant such as
    // `name =value` (which the parser also treats as `name`) counts as a second occurrence.
    return raw.split(';').filter((part) => {
        const eq = part.indexOf('=');
        return eq !== -1 && part.slice(0, eq).trim() === name;
    }).length;
}

/** The value of a cookie the IdP set; undefined when absent or not a string; throws if it occurs twice. */
export function readCookie(req, name) {
    if (occurrences(req, name) > 1) throw COOKIE_CONFLICT();
    const value = req.cookies?.[name];
    return typeof value === 'string' ? value : undefined;
}

/** The value of a session cookie (see sessionCookieName). */
export function readSessionCookie(state, req, base) {
    return readCookie(req, sessionCookieName(state, base));
}
