import { IdpError } from '../errors/idp-error.js';
import { hashOpaqueToken, opaqueTokenHashes, HASH_PURPOSES } from '../signing/token.service.js';

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

/**
 * The refresh-token cookie is scoped to the session endpoints (`<mount path>/session`), so the
 * long-lived token is sent nowhere else. A path-scoped cookie can't carry the `__Host-` prefix — the
 * one thing a sibling subdomain can't plant — so it is `__Secure-`, and comes with a host-only
 * BINDING cookie (`__Host-refresh_binding`, `Path=/`) holding a keyed hash of the token. A refresh
 * cookie is only accepted with its binding: a planted one (whose binding the planter can't set) is
 * refused. The binding alone is useless — it is not the token. With `cookies.domain` (cookies shared
 * across subdomains by choice) both are domain cookies, as before.
 */
export function refreshCookieNames(state) {
    if (!cookiesAreSecure(state)) return { token: 'refresh_token', binding: 'refresh_binding' };
    return { token: '__Secure-refresh_token', binding: state.config.cookies?.domain ? '__Secure-refresh_binding' : '__Host-refresh_binding' };
}

/**
 * The path the refresh cookie is scoped to: `cookies.sessionPath` when configured, otherwise the session
 * endpoints under wherever the router is mounted (as the request spelled it).
 */
export const sessionCookiePath = (state, req) => state.config.cookies?.sessionPath ?? `${req.baseUrl ?? ''}/session`;

export const refreshCookieBinding = (state, token) => hashOpaqueToken(state, token, HASH_PURPOSES.REFRESH_COOKIE_BINDING);

/** Every value of cookie `name` in the raw Cookie header, decoded the way the cookie parser decodes them. */
function allCookieValues(req, name) {
    const raw = req.headers?.cookie;
    if (typeof raw !== 'string') return [];
    const values = [];
    for (const part of raw.split(';')) {
        const eq = part.indexOf('=');
        if (eq === -1 || part.slice(0, eq).trim() !== name) continue;
        let value = part.slice(eq + 1).trim();
        if (value.length > 1 && value.startsWith('"') && value.endsWith('"')) value = value.slice(1, -1);
        try {
            value = decodeURIComponent(value);
        } catch {
            // left as sent, like the parser does
        }
        values.push(value);
    }
    return values;
}

/**
 * The refresh token from its cookie: the one value whose keyed hash its binding cookie holds. Values
 * without a matching binding (planted — the binding is host-only) are ignored, so a planted cookie
 * can neither be used nor block the real one. undefined when none matches; COOKIE_CONFLICT only when
 * two different tokens each come with a matching binding — possible only with `cookies.domain`, where
 * the binding is a domain cookie too.
 */
export function readRefreshCookie(state, req) {
    const names = refreshCookieNames(state);
    const bindings = new Set(allCookieValues(req, names.binding));
    // A browser holds one host-only binding; several can only be forged (or, with cookies.domain, planted).
    if (bindings.size === 0 || (bindings.size > MAX_BINDINGS(state))) return undefined;
    const tokens = [...new Set(allCookieValues(req, names.token))].slice(0, MAX_REFRESH_VALUES);
    // One keyed hash per token and key, looked up in the set (linear; both values come from the client,
    // so a constant-time comparison protects nothing here).
    const bound = tokens.filter((token) => opaqueTokenHashes(state, token, HASH_PURPOSES.REFRESH_COOKIE_BINDING).some((h) => bindings.has(h)));
    if (bound.length > 1) throw COOKIE_CONFLICT();
    return bound[0];
}

/** How many refresh-cookie values are considered at all (a real browser sends one or two). */
const MAX_REFRESH_VALUES = 8;
const MAX_BINDINGS = (state) => (state.config.cookies?.domain ? MAX_REFRESH_VALUES : 1);
