import { SESSION_KINDS } from '../config/constants.js';

/**
 * The kind of a session (refresh-token) row. Rows written since 0.4.0 carry `kind` explicitly. Older
 * rows don't: an OAuth2 grant always stored `claims: { clientId, scopes: [...] }`, so that shape is
 * read as `oauth2`; anything else as `first_party`. The inference fails closed — a first-party row
 * whose consumer claims happen to look like that is refused by `/refresh`, forcing a fresh login,
 * never accepted somewhere it shouldn't be.
 */
export function sessionKindOf(session) {
    if (session?.kind === SESSION_KINDS.FIRST_PARTY || session?.kind === SESSION_KINDS.OAUTH2) return session.kind;
    const claims = session?.claims;
    if (claims && typeof claims.clientId === 'string' && Array.isArray(claims.scopes)) return SESSION_KINDS.OAUTH2;
    return SESSION_KINDS.FIRST_PARTY;
}
