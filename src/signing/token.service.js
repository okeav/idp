import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import { getActiveSigningKey, getVerifiableKeys, getPublicKeyByKid } from './key-registry.js';
import { IdpError } from '../errors/idp-error.js';
import { TOKEN_TYPES } from '../config/constants.js';

const ALGORITHM = 'RS256';

/**
 * @param {object} state - the initialized IDP state (see config/state.js)
 * @param {{ sub: string, email?: string, claims?: Record<string, unknown> }} input
 * @param {{ ttlSeconds?: number, audience?: string }} [opts]
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
    };

    const token = jwt.sign(payload, key.privateKeyPem, { algorithm: ALGORITHM, keyid: kid });
    return { token, expiresAt: new Date(expiresAt * 1000), kid, jti: payload.jti };
}

export async function verifyAccessToken(state, token, opts = {}) {
    const payload = await verifyWithAnyKey(state, token, { issuer: opts.issuer ?? state.config.issuer });
    if (payload.type !== TOKEN_TYPES.ACCESS) {
        throw new IdpError({ code: 'INVALID_TOKEN', httpStatus: 401, message: 'Token is not an access token' });
    }
    return payload;
}

export async function issueIdToken(state, user, audience, nonce) {
    const now = Math.floor(Date.now() / 1000);
    const expiresAt = now + state.config.ttls.idToken;
    const [kid, key] = getActiveSigningKey(state.signingKeys);

    const claims = {
        sub: String(user.id),
        email: user.email,
        email_verified: user.status !== 'PENDING_VERIFICATION',
        name: user.profile?.displayName || [user.profile?.firstName, user.profile?.lastName].filter(Boolean).join(' ') || undefined,
        given_name: user.profile?.firstName || undefined,
        family_name: user.profile?.lastName || undefined,
        picture: user.profile?.avatarUrl || undefined,
        locale: user.profile?.locale || undefined,
        zoneinfo: user.profile?.zoneinfo || undefined,
        aud: audience,
        iss: state.config.issuer,
        jti: crypto.randomUUID(),
        iat: now,
        exp: expiresAt,
        ...(nonce ? { nonce } : {}),
    };
    Object.keys(claims).forEach((k) => claims[k] === undefined && delete claims[k]);

    const token = jwt.sign(claims, key.privateKeyPem, { algorithm: ALGORITHM, keyid: kid });
    return { token, expiresAt: new Date(expiresAt * 1000), kid, jti: claims.jti };
}

export async function issueOAuth2AccessToken(state, subject, client, scopes) {
    const now = Math.floor(Date.now() / 1000);
    const ttl = client.accessTokenTTL || state.config.ttls.accessToken;
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
    };

    const token = jwt.sign(claims, key.privateKeyPem, { algorithm: ALGORITHM, keyid: kid });
    return { token, expiresAt: new Date(expiresAt * 1000), kid, jti: claims.jti };
}

export async function issueMfaChallengeToken(state, subjectId) {
    const now = Math.floor(Date.now() / 1000);
    const expiresAt = now + state.config.ttls.mfaChallenge;
    const [kid, key] = getActiveSigningKey(state.signingKeys);

    const claims = {
        sub: String(subjectId),
        type: TOKEN_TYPES.MFA_CHALLENGE,
        iss: state.config.issuer,
        jti: crypto.randomUUID(),
        iat: now,
        exp: expiresAt,
    };

    return jwt.sign(claims, key.privateKeyPem, { algorithm: ALGORITHM, keyid: kid });
}

export function verifyMfaChallengeToken(state, token) {
    for (const [, key] of getVerifiableKeys(state.signingKeys)) {
        try {
            const decoded = jwt.verify(token, key.publicKeyPem, { algorithms: [ALGORITHM] });
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
            });
        } catch {
            // try next key
        }
    }
    return null;
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

// ── Opaque-token hashing (refresh tokens, password-reset / email-verification tokens) ──

export function hashOpaqueToken(state, rawToken) {
    return crypto.createHmac('sha256', state.config.security.tokenHashSecret).update(rawToken).digest('hex');
}

export function generateOpaqueToken(byteLength = 64) {
    return crypto.randomBytes(byteLength).toString('hex');
}
