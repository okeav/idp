import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import { getActiveSigningKey, getVerifiableKeys, getPublicKeyByKid } from './key-registry.js';
import { IdpError } from '../errors/idp-error.js';
import { TOKEN_TYPES, ACCESS_TOKEN_KINDS, GRANT_TYPES } from '../config/constants.js';

const ALGORITHM = 'RS256';

/**
 * @param {object} state - the initialized IDP state (see config/state.js)
 * @param {{ sub: string, email?: string, claims?: Record<string, unknown> }} input
 * @param {{ ttlSeconds?: number, audience?: string, sessionless?: boolean, authTime?: number }} [opts] - `sessionless: true`
 *   marks a token that has no session row behind it, so authContextMiddleware's per-request session
 *   check (`session.verifyOnEachRequest`) skips it instead of refusing it. Internal session-backed
 *   issuance (login, refresh) never sets it.
 */
export async function issueAccessToken(state, input, opts = {}) {
    const { sub, email, claims = {} } = input;
    if (!sub) throw new IdpError({ code: 'MISSING_REQUIRED_FIELDS', httpStatus: 400, message: 'sub is required to issue an access token' });

    const issuedAt = Math.floor(Date.now() / 1000);
    const ttl = opts.ttlSeconds ?? state.config.ttls.accessToken;
    const expiresAt = issuedAt + ttl;
    const [kid, key] = getActiveSigningKey(state.signingKeys);

    const payload = {
        sub,
        email,
        claims,
        type: TOKEN_TYPES.ACCESS,
        iss: state.config.issuer,
        aud: opts.audience ?? state.config.issuer,
        jti: crypto.randomUUID(),
        iat: issuedAt,
        exp: expiresAt,
        // When the user last actually authenticated (seconds) — carried unchanged across refreshes,
        // so requireRecentAuth can demand a fresh login before sensitive changes.
        ...(Number.isInteger(opts.authTime) ? { auth_time: opts.authTime } : {}),
        ...(opts.sessionless ? { sessionless: true } : {}),
    };

    const token = jwt.sign(payload, key.privateKeyPem, { algorithm: ALGORITHM, keyid: kid });
    return { token, expiresAt: new Date(expiresAt * 1000), kid, jti: payload.jti };
}

/**
 * Which party an access token was issued to:
 * - `first-party`  — this IdP's own login/refresh (and the public `issueAccessToken()` export). No `client_id`.
 * - `oauth2-user`  — issued to an OAuth2 client on behalf of a user (authorization_code / refresh_token grants).
 * - `oauth2-client` — a client_credentials machine token; the client itself is the subject, there is no user.
 */
/** Upper bounds for a client's own token lifetimes (also enforced at registration; this covers older rows). */
export const MAX_CLIENT_TTL_SECONDS = Object.freeze({ accessTokenTTL: 24 * 60 * 60, idTokenTTL: 24 * 60 * 60, refreshTokenTTL: 365 * 24 * 60 * 60 });

/** A client's configured lifetime for `key`, or `fallback` — never above MAX_CLIENT_TTL_SECONDS. */
export function clientTtl(client, key, fallback) {
    const value = Number.isInteger(client?.[key]) && client[key] > 0 ? client[key] : fallback;
    return value === undefined ? undefined : Math.min(value, MAX_CLIENT_TTL_SECONDS[key]);
}

export function classifyAccessToken(payload) {
    if (!payload?.client_id) return ACCESS_TOKEN_KINDS.FIRST_PARTY;
    if (payload.gty === GRANT_TYPES.CLIENT_CREDENTIALS || payload.sub === payload.client_id) return ACCESS_TOKEN_KINDS.OAUTH2_CLIENT;
    return ACCESS_TOKEN_KINDS.OAUTH2_USER;
}

const INVALID_AUDIENCE = (message) => new IdpError({ code: 'INVALID_TOKEN', httpStatus: 401, message });

/**
 * Verifies signature, issuer, expiry, `type: access_token`, AND which party the token was issued to.
 *
 * @param {{ issuer?: string, audience?: string | string[], accept?: Array<'first-party'|'oauth2-user'|'oauth2-client'> }} [opts]
 *   `accept` defaults to `['first-party']`: an access token minted for a third-party OAuth2 client
 *   (aud = that client) is NOT a credential for this IdP's own routes — otherwise any relying party a
 *   user authorized could act as that user here. `audience` is the `aud` a first-party token must carry
 *   (default: the issuer). OAuth2 tokens must carry `aud === client_id`.
 */
export async function verifyAccessToken(state, token, opts = {}) {
    const payload = await verifyWithAnyKey(state, token, { issuer: opts.issuer ?? state.config.issuer });
    if (payload.type !== TOKEN_TYPES.ACCESS) {
        throw new IdpError({ code: 'INVALID_TOKEN', httpStatus: 401, message: 'Token is not an access token' });
    }

    const accept = opts.accept ?? [ACCESS_TOKEN_KINDS.FIRST_PARTY];
    const kind = classifyAccessToken(payload);
    if (!accept.includes(kind)) {
        throw INVALID_AUDIENCE(`Token kind "${kind}" is not accepted here`);
    }

    const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    if (kind === ACCESS_TOKEN_KINDS.FIRST_PARTY) {
        const expected = [].concat(opts.audience ?? state.config.issuer);
        if (!audiences.some((a) => expected.includes(a))) throw INVALID_AUDIENCE('Token audience is not accepted here');
    } else if (!audiences.includes(payload.client_id)) {
        throw INVALID_AUDIENCE('Token audience does not match its client');
    }
    return payload;
}

/**
 * @param {{ scopes?: string[], authTime?: number, ttlSeconds?: number }} [opts] - `scopes` decide
 *   which user claims are released (OIDC Core §5.4: `email` → email + email_verified, `profile` →
 *   name, picture, locale …). Default: openid email profile (the pre-0.4.0 behaviour, kept for the
 *   public export). `authTime` (seconds) becomes `auth_time`.
 */
export async function issueIdToken(state, user, audience, nonce, opts = {}) {
    const now = Math.floor(Date.now() / 1000);
    const expiresAt = now + (opts.ttlSeconds ?? state.config.ttls.idToken);
    const [kid, key] = getActiveSigningKey(state.signingKeys);
    const scopes = new Set(opts.scopes ?? ['openid', 'email', 'profile']);

    const claims = {
        sub: String(user.id),
        ...(scopes.has('email') ? { email: user.email, email_verified: user.status !== 'PENDING_VERIFICATION' } : {}),
        ...(scopes.has('profile') ? {
            name: user.profile?.displayName || [user.profile?.firstName, user.profile?.lastName].filter(Boolean).join(' ') || undefined,
            given_name: user.profile?.firstName || undefined,
            family_name: user.profile?.lastName || undefined,
            picture: user.profile?.avatarUrl || undefined,
            locale: user.profile?.locale || undefined,
            zoneinfo: user.profile?.zoneinfo || undefined,
        } : {}),
        aud: audience,
        azp: audience,
        iss: state.config.issuer,
        jti: crypto.randomUUID(),
        iat: now,
        exp: expiresAt,
        ...(Number.isInteger(opts.authTime) ? { auth_time: opts.authTime } : {}),
        ...(nonce ? { nonce } : {}),
    };
    Object.keys(claims).forEach((k) => claims[k] === undefined && delete claims[k]);

    const token = jwt.sign(claims, key.privateKeyPem, { algorithm: ALGORITHM, keyid: kid });
    return { token, expiresAt: new Date(expiresAt * 1000), kid, jti: claims.jti };
}

export async function issueOAuth2AccessToken(state, subject, client, scopes, { sessionless = false, grantType } = {}) {
    const now = Math.floor(Date.now() / 1000);
    const ttl = clientTtl(client, 'accessTokenTTL', state.config.ttls.accessToken);
    const expiresAt = now + ttl;
    const [kid, key] = getActiveSigningKey(state.signingKeys);

    const claims = {
        sub: String(subject.id),
        // Top-level `scope`/`client_id` per OAuth2/OIDC convention (RFC 6749,
        // RFC 7519) for resource servers that read raw JWT claims directly —
        // also nested under `claims` so this token verifies through the same
        // `verifyAccessToken`/`authContextMiddleware` path as password- and
        // SSO-issued tokens (both require `type: 'access_token'`, which a
        // flat OAuth2-only claim set would otherwise lack).
        scope: scopes.join(' '),
        client_id: client.clientId,
        claims: { scope: scopes.join(' '), clientId: client.clientId },
        type: TOKEN_TYPES.ACCESS,
        aud: client.clientId,
        iss: state.config.issuer,
        jti: crypto.randomUUID(),
        iat: now,
        exp: expiresAt,
        // Marks a machine token (no user) so it can never pass as a user identity — see classifyAccessToken.
        ...(grantType === GRANT_TYPES.CLIENT_CREDENTIALS ? { gty: GRANT_TYPES.CLIENT_CREDENTIALS } : {}),
        ...(sessionless ? { sessionless: true } : {}),
    };

    const token = jwt.sign(claims, key.privateKeyPem, { algorithm: ALGORITHM, keyid: kid });
    return { token, expiresAt: new Date(expiresAt * 1000), kid, jti: claims.jti };
}

/**
 * `opts.sessionEpoch`: the user's sessionEpoch as read BEFORE the first factor was checked. The
 * challenge is refused at /mfa/verify if the user's sessions were revoked since (password reset,
 * logout-all), and the session it completes belongs to that epoch.
 */
export async function issueMfaChallengeToken(state, subjectId, { sessionEpoch } = {}) {
    const now = Math.floor(Date.now() / 1000);
    const expiresAt = now + state.config.ttls.mfaChallenge;
    const [kid, key] = getActiveSigningKey(state.signingKeys);

    const claims = {
        sub: String(subjectId),
        type: TOKEN_TYPES.MFA_CHALLENGE,
        iss: state.config.issuer,
        aud: mfaChallengeAudience(state),
        jti: crypto.randomUUID(),
        iat: now,
        exp: expiresAt,
        ...(Number.isInteger(sessionEpoch) ? { sep: sessionEpoch } : {}),
    };

    return jwt.sign(claims, key.privateKeyPem, { algorithm: ALGORITHM, keyid: kid });
}

const mfaChallengeAudience = (state) => `${state.config.issuer}#mfa-challenge`;

export function verifyMfaChallengeToken(state, token) {
    for (const [, key] of getVerifiableKeys(state.signingKeys)) {
        try {
            // Issuer and audience pinned: a challenge from another environment sharing a signing key
            // (or any other token type) is not one of ours.
            const decoded = jwt.verify(token, key.publicKeyPem, { algorithms: [ALGORITHM], issuer: state.config.issuer, audience: mfaChallengeAudience(state) });
            if (decoded.type !== TOKEN_TYPES.MFA_CHALLENGE) continue;
            return decoded;
        } catch {
            // try next key
        }
    }
    throw new IdpError({ code: 'INVALID_MFA_CHALLENGE_TOKEN', httpStatus: 401, message: 'Invalid or expired MFA challenge token' });
}

/** Generic "did we issue this" verification — returns null instead of throwing. Used by end-session's id_token_hint. */
export function verifyIssuedToken(state, token, opts = {}) {
    if (!token || typeof token !== 'string') return null;
    for (const [, key] of getVerifiableKeys(state.signingKeys)) {
        try {
            return jwt.verify(token, key.publicKeyPem, {
                algorithms: [ALGORITHM],
                ...(opts.issuer ? { issuer: opts.issuer } : {}),
                ...(opts.ignoreExpiration ? { ignoreExpiration: true } : {}),
            });
        } catch {
            // try next key
        }
    }
    return null;
}

/**
 * True for an ID token this IdP issued (verify the signature first): no `type` (access and MFA
 * challenge tokens have one), no `client_id` (OAuth2 access tokens have one), and an audience that
 * is a client — never the IdP itself.
 */
export function isIdTokenPayload(state, payload) {
    return Boolean(payload) && payload.type === undefined && payload.client_id === undefined
        && typeof payload.aud === 'string' && payload.aud !== state.config.issuer && typeof payload.sub === 'string';
}

async function verifyWithAnyKey(state, token, { issuer } = {}) {
    const decoded = jwt.decode(token, { complete: true });
    const kid = decoded?.header?.kid;
    const publicKeyPem = kid ? getPublicKeyByKid(state.signingKeys, kid) : null;

    const tryVerify = (pem) => jwt.verify(token, pem, { algorithms: [ALGORITHM], clockTolerance: 30, ...(issuer ? { issuer } : {}) });

    try {
        if (publicKeyPem) return tryVerify(publicKeyPem);
        // Unknown/missing kid — fall through to trying every verifiable key.
        for (const [, key] of getVerifiableKeys(state.signingKeys)) {
            try { return tryVerify(key.publicKeyPem); } catch { /* try next */ }
        }
        throw new Error('no matching key');
    } catch (err) {
        if (err?.name === 'TokenExpiredError') {
            throw new IdpError({ code: 'TOKEN_EXPIRED', httpStatus: 401, message: 'Token expired' });
        }
        throw new IdpError({ code: 'INVALID_TOKEN', httpStatus: 401, message: 'Invalid token', cause: err });
    }
}

// ── Opaque-token hashing (refresh tokens, codes, links, recovery codes, client secrets) ──

/**
 * What a keyed hash is for. Each purpose gets its own key, derived from `security.tokenHashSecret`
 * (HKDF-SHA256, the purpose as `info`): a hash made for one purpose never verifies as another, and
 * no stored hash is keyed by the secret itself.
 */
export const HASH_PURPOSES = Object.freeze({
    REFRESH_TOKEN: 'refresh-token',
    AUTHORIZATION_CODE: 'authorization-code',
    EMAIL_VERIFICATION_LINK: 'email-verification-link',
    EMAIL_VERIFICATION_CODE: 'email-verification-code',
    EMAIL_VERIFICATION_TICKET: 'email-verification-ticket',
    PASSWORD_RESET: 'password-reset',
    MAGIC_LINK: 'magic-link',
    MFA_RECOVERY_CODE: 'mfa-recovery-code',
    OAUTH_CLIENT_SECRET: 'oauth-client-secret',
    ACCESS_TOKEN_AUDIT: 'access-token-audit',
    WEBAUTHN_DECOY: 'webauthn-decoy',
});
const PURPOSES = new Set(Object.values(HASH_PURPOSES));
const HKDF_SALT = 'okeav/idp-core token-hash v1';
const derivedKeys = new Map();

function derivedKey(secret, purpose) {
    const id = `${purpose}\u0000${secret}`;
    let key = derivedKeys.get(id);
    if (!key) {
        key = Buffer.from(crypto.hkdfSync('sha256', secret, HKDF_SALT, purpose, 32));
        derivedKeys.set(id, key);
    }
    return key;
}

/**
 * The keys for `purpose`: the current one (from `security.tokenHashSecret`) first, then one per
 * `security.previousTokenHashSecrets` — so the secret can be rotated: new hashes use the current key,
 * while everything stored under a previous one still verifies until it expires or is replaced.
 */
export function tokenHashKeys(state, purpose) {
    if (!PURPOSES.has(purpose)) throw new Error(`Unknown token-hash purpose: ${purpose}`);
    const { tokenHashSecret, previousTokenHashSecrets = [] } = state.config.security;
    return [tokenHashSecret, ...previousTokenHashSecrets].map((secret) => derivedKey(secret, purpose));
}

const hmacHex = (key, value) => crypto.createHmac('sha256', key).update(String(value)).digest('hex');

/** The hash to STORE for `rawToken` — always under the current key. */
export function hashOpaqueToken(state, rawToken, purpose) {
    return hmacHex(tokenHashKeys(state, purpose)[0], rawToken);
}

/** Every hash `rawToken` may be stored under: the current key's first, then each previous key's. */
export function opaqueTokenHashes(state, rawToken, purpose) {
    return tokenHashKeys(state, purpose).map((key) => hmacHex(key, rawToken));
}

/**
 * Looks `rawToken` up under each of its candidate hashes (opaqueTokenHashes), in order, until
 * `lookup(hash)` returns something. Resolves `{ result, hash }` — the hash that matched, or (no match)
 * the current one with a null result. With no previous secrets this is a single lookup.
 */
export async function lookupByTokenHash(state, rawToken, purpose, lookup) {
    const hashes = opaqueTokenHashes(state, rawToken, purpose);
    for (const hash of hashes) {
        const result = await lookup(hash);
        if (result) return { result, hash };
    }
    return { result: null, hash: hashes[0] };
}

export function generateOpaqueToken(byteLength = 64) {
    return crypto.randomBytes(byteLength).toString('hex');
}
