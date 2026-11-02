import crypto from 'crypto';
import { getState } from '../config/state.js';
import { IdpError } from '../errors/idp-error.js';
import { IDENTITY_STATUS, GRANT_TYPES, CACHE_KEY_PREFIXES, SESSION_KINDS, ACCESS_TOKEN_KINDS } from '../config/constants.js';
import { issueOAuth2AccessToken, issueIdToken, hashOpaqueToken, generateOpaqueToken, verifyAccessToken } from '../signing/token.service.js';
import { sessionKindOf } from '../utils/session-kind.js';
import { authenticateClient } from './client-auth.js';
import { auditLog } from '../hooks/index.js';
import { enforceRateLimit } from '../rate-limit/enforce.js';

const INVALID_GRANT = (message) => new IdpError({ code: 'INVALID_GRANT', httpStatus: 400, message });

/**
 * RFC 7636 with S256 only. A code issued with a challenge needs the matching verifier; a code issued
 * WITHOUT one must not be redeemed with a verifier either (RFC 9700 §4.8.2) — that combination is a
 * PKCE downgrade: an attacker injecting a challenge-less code into a client that uses PKCE.
 */
function verifyPkce(codeVerifier, authCode) {
    if (!authCode.codeChallenge) {
        if (codeVerifier) throw INVALID_GRANT('code_verifier sent for a code issued without code_challenge');
        return;
    }
    if (authCode.codeChallengeMethod !== 'S256') throw INVALID_GRANT('Unsupported code_challenge_method');
    if (!codeVerifier) throw INVALID_GRANT('code_verifier is required');
    const computed = Buffer.from(crypto.createHash('sha256').update(codeVerifier).digest('base64url'));
    const stored = Buffer.from(authCode.codeChallenge);
    if (computed.length !== stored.length || !crypto.timingSafeEqual(computed, stored)) throw INVALID_GRANT('PKCE verification failed');
}

/** A client must be explicitly registered for the grant it's trying to use — `allowedGrants` isn't decorative. */
function assertGrantAllowed(client, grantType) {
    if (!client.allowedGrants?.includes(grantType)) {
        throw new IdpError({ code: 'UNAUTHORIZED_CLIENT', httpStatus: 400, message: `Client is not authorized to use grant_type "${grantType}"` });
    }
}

/** RFC 6749 §5.1: token responses MUST NOT be cached. Also applied to revoke/introspect. */
function noStore(res) {
    res.set('Cache-Control', 'no-store');
    res.set('Pragma', 'no-cache');
}

async function limitTokenEndpoint(state, req) {
    await enforceRateLimit(state, `oauth2-token:ip:${req.ip}`, state.config.rateLimiting.oauth2Token, { failMode: 'closed' });
}

/** POST /oauth2/token */
export async function tokenHandler(req, res, next) {
    try {
        noStore(res);
        const state = getState();
        await limitTokenEndpoint(state, req);
        const { grant_type } = req.body;
        // `await` matters: without it a rejected grant escapes this try/catch, and on Express 4
        // (which ignores returned promises) becomes an unhandledRejection that kills the process.
        if (grant_type === 'authorization_code') return await handleAuthorizationCodeGrant(req, res, next);
        if (grant_type === 'refresh_token') return await handleRefreshTokenGrant(req, res, next);
        if (grant_type === 'client_credentials') return await handleClientCredentialsGrant(req, res, next);
        throw new IdpError({ code: 'UNSUPPORTED_GRANT_TYPE', httpStatus: 400, message: `Unsupported grant_type: ${grant_type}` });
    } catch (err) {
        next(err);
    }
}

async function handleAuthorizationCodeGrant(req, res) {
    const state = getState();
    const { code, redirect_uri, code_verifier } = req.body;
    if (!code || !redirect_uri) throw new IdpError({ code: 'MISSING_REQUIRED_FIELDS', httpStatus: 400, message: 'code and redirect_uri are required' });

    const client = await authenticateClient(state, req);
    assertGrantAllowed(client, GRANT_TYPES.AUTHORIZATION_CODE);
    const authCode = await state.storage.authorizationCodeRepository.consumeByCodeHash(hashOpaqueToken(state, code));
    if (!authCode) throw INVALID_GRANT('Invalid or expired authorization code');
    if (authCode.clientId !== client.clientId) throw INVALID_GRANT('Authorization code was issued to another client');
    if (authCode.redirectUri !== redirect_uri) throw INVALID_GRANT('redirect_uri mismatch');
    verifyPkce(code_verifier, authCode);

    const user = await state.storage.userRepository.findById(authCode.userId);
    if (!user || user.status !== IDENTITY_STATUS.ACTIVE) throw INVALID_GRANT('User account is not active');

    const scopes = authCode.scopes || [];
    const accessTokenResult = await issueOAuth2AccessToken(state, user, client, scopes);
    const refreshTokenValue = generateOpaqueToken();
    const refreshExpiresAt = new Date(Date.now() + (client.refreshTokenTTL || state.config.ttls.refreshToken) * 1000);

    await state.storage.sessionRepository.createSession({
        user: user.id, tokenHash: hashOpaqueToken(state, refreshTokenValue), expiresAt: refreshExpiresAt,
        kid: accessTokenResult.kid, jti: accessTokenResult.jti, ipAddress: req.ip, deviceInfo: req.headers['user-agent'],
        kind: SESSION_KINDS.OAUTH2, claims: { clientId: client.clientId, scopes },
    });

    const idToken = scopes.includes('openid')
        ? await issueIdToken(state, user, client.clientId, authCode.nonce || undefined, {
            scopes,
            authTime: authCode.authTime ? Math.floor(new Date(authCode.authTime).getTime() / 1000) : undefined,
            ttlSeconds: client.idTokenTTL || undefined,
        })
        : null;

    await auditLog(state.logger, state.hooks, 'OAUTH2_TOKEN_ISSUED', { userId: String(user.id), clientId: client.clientId, grantType: 'authorization_code', scopes });

    res.json({
        access_token: accessTokenResult.token,
        refresh_token: refreshTokenValue,
        ...(idToken ? { id_token: idToken.token } : {}),
        token_type: 'Bearer',
        expires_in: client.accessTokenTTL || state.config.ttls.accessToken,
        scope: scopes.join(' '),
    });
}

async function handleRefreshTokenGrant(req, res) {
    const state = getState();
    const { refresh_token } = req.body;
    if (!refresh_token) throw new IdpError({ code: 'MISSING_REQUIRED_FIELDS', httpStatus: 400, message: 'refresh_token is required' });

    const client = await authenticateClient(state, req);
    assertGrantAllowed(client, GRANT_TYPES.REFRESH_TOKEN);
    const existing = await state.storage.sessionRepository.revokeByRefreshTokenHash(hashOpaqueToken(state, refresh_token));
    if (!existing) throw INVALID_GRANT('Invalid or expired refresh token');
    // RFC 6749 §6: a refresh token is bound to the client it was issued to. A first-party login's
    // refresh token, or another client's, is refused — and stays revoked (consumed above), since
    // presenting it here means it leaked.
    if (sessionKindOf(existing) !== SESSION_KINDS.OAUTH2 || existing.claims?.clientId !== client.clientId) {
        state.logger?.warn?.({ clientId: client.clientId }, 'Refresh token presented by a client it was not issued to — refused and revoked');
        throw INVALID_GRANT('Invalid or expired refresh token');
    }

    const user = await state.storage.userRepository.findById(existing.user);
    if (!user || user.status !== IDENTITY_STATUS.ACTIVE) throw INVALID_GRANT('User account is not active');

    // Refreshing must never grant more than the user originally consented to — narrow the
    // originally-granted scopes to whatever the client is still allowed, don't recompute from scratch.
    const grantedScopes = existing.claims?.scopes || [];
    const allowedScopes = new Set(client.allowedScopes || []);
    const scopes = grantedScopes.filter((s) => s === 'openid' || allowedScopes.has(s));
    const accessTokenResult = await issueOAuth2AccessToken(state, user, client, scopes);
    const newRefreshTokenValue = generateOpaqueToken();
    const refreshExpiresAt = new Date(Date.now() + (client.refreshTokenTTL || state.config.ttls.refreshToken) * 1000);

    await state.storage.sessionRepository.createSession({
        user: user.id, tokenHash: hashOpaqueToken(state, newRefreshTokenValue), expiresAt: refreshExpiresAt,
        kid: accessTokenResult.kid, jti: accessTokenResult.jti, ipAddress: req.ip, deviceInfo: req.headers['user-agent'],
        kind: SESSION_KINDS.OAUTH2, claims: { clientId: client.clientId, scopes },
    });

    if (existing.jti) await state.cache.set(`${CACHE_KEY_PREFIXES.REVOKED_REFRESH_TOKEN}:${existing.jti}`, '1', state.config.ttls.revocationCache);

    await auditLog(state.logger, state.hooks, 'OAUTH2_TOKEN_ISSUED', { userId: String(user.id), clientId: client.clientId, grantType: 'refresh_token' });

    res.json({
        access_token: accessTokenResult.token, refresh_token: newRefreshTokenValue, token_type: 'Bearer',
        expires_in: client.accessTokenTTL || state.config.ttls.accessToken, scope: scopes.join(' '),
    });
}

/**
 * RFC 6749 §4.4 — machine-to-machine grant, no end user involved. The
 * client authenticates as itself and gets a token representing itself, not
 * a resource owner. Confidential clients only (a public client can't prove
 * its own identity without a secret, and there's no PKCE equivalent for
 * this grant). No refresh token is issued, per spec — the client just
 * re-authenticates with its credentials whenever it needs a new one.
 */
async function handleClientCredentialsGrant(req, res) {
    const state = getState();
    const { scope } = req.body;

    const client = await authenticateClient(state, req, { requireConfidential: true });
    assertGrantAllowed(client, GRANT_TYPES.CLIENT_CREDENTIALS);

    const allowed = new Set(client.allowedScopes || []);
    const requestedScopes = scope ? scope.split(' ').filter(Boolean) : [...allowed];
    const invalidScopes = requestedScopes.filter((s) => !allowed.has(s));
    if (invalidScopes.length > 0) {
        throw new IdpError({ code: 'INVALID_SCOPE', httpStatus: 400, message: `Requested scopes not allowed: ${invalidScopes.join(', ')}` });
    }

    // No user, no refresh token, no session row — marked sessionless so the
    // per-request session check doesn't refuse it.
    const accessTokenResult = await issueOAuth2AccessToken(state, { id: client.clientId }, client, requestedScopes, { sessionless: true, grantType: GRANT_TYPES.CLIENT_CREDENTIALS });

    await auditLog(state.logger, state.hooks, 'OAUTH2_TOKEN_ISSUED', { clientId: client.clientId, grantType: 'client_credentials', scopes: requestedScopes });

    res.json({
        access_token: accessTokenResult.token,
        token_type: 'Bearer',
        expires_in: client.accessTokenTTL || state.config.ttls.accessToken,
        scope: requestedScopes.join(' '),
    });
}

const looksLikeJwt = (token) => /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(token);

/**
 * Resolves a token presented to revoke/introspect to its OAuth2 session row — but only a token issued
 * to `client`. First-party tokens and other clients' tokens resolve to nothing.
 */
async function findClientSession(state, client, token) {
    const sessions = state.storage.sessionRepository;
    if (looksLikeJwt(token)) {
        let payload;
        try {
            payload = await verifyAccessToken(state, token, { accept: [ACCESS_TOKEN_KINDS.OAUTH2_USER, ACCESS_TOKEN_KINDS.OAUTH2_CLIENT] });
        } catch {
            return null;
        }
        if (payload.client_id !== client.clientId) return null;
        if (payload.sessionless) return { payload, session: null };
        const session = await sessions.findByJti(payload.jti);
        return session ? { payload, session } : null;
    }
    const session = await sessions.findByRefreshTokenHash(hashOpaqueToken(state, token));
    if (!session || sessionKindOf(session) !== SESSION_KINDS.OAUTH2 || session.claims?.clientId !== client.clientId) return null;
    return { payload: null, session };
}

/**
 * POST /oauth2/token/revoke — RFC 7009. The client must authenticate (a public client by its id),
 * and only tokens issued to it are revoked; anything else is silently ignored. Always 200.
 */
export async function revokeTokenHandler(req, res, next) {
    try {
        noStore(res);
        const state = getState();
        await limitTokenEndpoint(state, req);
        const client = await authenticateClient(state, req);

        const found = await findClientSession(state, client, req.body.token);
        if (found?.session && !found.session.revokedAt) {
            const sessions = state.storage.sessionRepository;
            if (found.payload) await sessions.revokeById(found.session.id, found.session.user);
            else await sessions.revokeByRefreshTokenHash(hashOpaqueToken(state, req.body.token), { onlyIfActive: false });
            if (found.session.jti) await state.cache.set(`${CACHE_KEY_PREFIXES.REVOKED_REFRESH_TOKEN}:${found.session.jti}`, '1', state.config.ttls.revocationCache);
            await auditLog(state.logger, state.hooks, 'OAUTH2_TOKEN_REVOKED', { clientId: client.clientId, userId: String(found.session.user) });
        }
        res.status(200).json({ status: 'ok' });
    } catch (err) {
        next(err);
    }
}

/**
 * POST /oauth2/token/introspect — RFC 7662. Callable only by an authenticated confidential client
 * (a resource server registered as a client), and it describes only tokens issued to that client;
 * anything else is `{ active: false }`. Handles both access tokens (JWT) and refresh tokens.
 */
export async function introspectTokenHandler(req, res, next) {
    try {
        noStore(res);
        const state = getState();
        await limitTokenEndpoint(state, req);
        const client = await authenticateClient(state, req, { requireConfidential: true });

        const found = await findClientSession(state, client, req.body.token);
        const session = found?.session;
        const live = session ? !session.revokedAt && new Date(session.expiresAt) > new Date() : Boolean(found?.payload);
        if (!found || !live) return res.json({ active: false });

        if (found.payload) {
            const p = found.payload;
            return res.json({ active: true, token_type: 'access_token', client_id: p.client_id, sub: p.sub, scope: p.scope, exp: p.exp, iat: p.iat, iss: p.iss, aud: p.aud, jti: p.jti });
        }
        res.json({
            active: true,
            token_type: 'refresh_token',
            client_id: client.clientId,
            sub: String(session.user),
            scope: (session.claims?.scopes || []).join(' '),
            exp: Math.floor(new Date(session.expiresAt).getTime() / 1000),
            iat: Math.floor(new Date(session.createdAt).getTime() / 1000),
        });
    } catch (err) {
        next(err);
    }
}
