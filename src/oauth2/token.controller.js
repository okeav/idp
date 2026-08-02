import crypto from 'crypto';
import { getState } from '../config/state.js';
import { IdpError } from '../errors/idp-error.js';
import { OAUTH_CLIENT_STATUS, IDENTITY_STATUS, CLIENT_TYPES, GRANT_TYPES, CACHE_KEY_PREFIXES } from '../config/constants.js';
import { issueOAuth2AccessToken, issueIdToken, hashOpaqueToken, generateOpaqueToken } from '../signing/token.service.js';
import { verifyClientSecret } from '../utils/oauth-client-credentials.js';
import { auditLog } from '../hooks/index.js';

function verifyPkce(codeVerifier, storedChallenge, method) {
    if (!storedChallenge) return; // not required for confidential clients
    if (!codeVerifier) throw new IdpError({ code: 'INVALID_REQUEST', httpStatus: 400, message: 'code_verifier is required' });
    const challenge = method === 'S256' ? crypto.createHash('sha256').update(codeVerifier).digest('base64url') : codeVerifier;
    if (challenge !== storedChallenge) throw new IdpError({ code: 'INVALID_REQUEST', httpStatus: 400, message: 'PKCE verification failed' });
}

async function authenticateClient(state, clientId, clientSecret) {
    const client = await state.storage.oauthClientRepository.findByClientId(clientId, { includeSecret: true });
    if (!client || client.status !== OAUTH_CLIENT_STATUS.ACTIVE) {
        throw new IdpError({ code: 'OAUTH_CLIENT_NOT_FOUND', httpStatus: 400, message: 'Unknown or inactive client' });
    }
    if (client.clientType === CLIENT_TYPES.CONFIDENTIAL) {
        if (!clientSecret) throw new IdpError({ code: 'INVALID_REQUEST', httpStatus: 401, message: 'client_secret is required for confidential clients' });
        if (!(await verifyClientSecret(clientSecret, client.clientSecretHash))) {
            throw new IdpError({ code: 'INVALID_CREDENTIALS', httpStatus: 401, message: 'Invalid client credentials' });
        }
    }
    return client;
}

/** A client must be explicitly registered for the grant it's trying to use — `allowedGrants` isn't decorative. */
function assertGrantAllowed(client, grantType) {
    if (!client.allowedGrants?.includes(grantType)) {
        throw new IdpError({ code: 'INVALID_REQUEST', httpStatus: 400, message: `Client is not authorized to use grant_type "${grantType}"` });
    }
}

/** POST /oauth2/token */
export async function tokenHandler(req, res, next) {
    try {
        const { grant_type } = req.body;
        if (grant_type === 'authorization_code') return handleAuthorizationCodeGrant(req, res, next);
        if (grant_type === 'refresh_token') return handleRefreshTokenGrant(req, res, next);
        if (grant_type === 'client_credentials') return handleClientCredentialsGrant(req, res, next);
        throw new IdpError({ code: 'INVALID_REQUEST', httpStatus: 400, message: `Unsupported grant_type: ${grant_type}` });
    } catch (err) {
        next(err);
    }
}

async function handleAuthorizationCodeGrant(req, res) {
    const state = getState();
    const { code, redirect_uri, client_id, client_secret, code_verifier, nonce } = req.body;
    if (!code || !redirect_uri) throw new IdpError({ code: 'MISSING_REQUIRED_FIELDS', httpStatus: 400, message: 'code and redirect_uri are required' });

    const client = await authenticateClient(state, client_id, client_secret);
    assertGrantAllowed(client, GRANT_TYPES.AUTHORIZATION_CODE);
    const codeHash = hashOpaqueToken(state, code);
    const authCode = await state.storage.authorizationCodeRepository.consumeByCodeHash(codeHash);
    if (!authCode) throw new IdpError({ code: 'INVALID_OR_EXPIRED_TOKEN', httpStatus: 400, message: 'Invalid or expired authorization code' });
    if (authCode.clientId !== client_id) throw new IdpError({ code: 'INVALID_REQUEST', httpStatus: 400, message: 'client_id mismatch' });
    if (authCode.redirectUri !== redirect_uri) throw new IdpError({ code: 'INVALID_REQUEST', httpStatus: 400, message: 'redirect_uri mismatch' });

    verifyPkce(code_verifier, authCode.codeChallenge, authCode.codeChallengeMethod);

    const user = await state.storage.userRepository.findById(authCode.userId);
    if (!user || user.status !== IDENTITY_STATUS.ACTIVE) throw new IdpError({ code: 'USER_NOT_ACTIVE', httpStatus: 400, message: 'User account is not active' });

    const scopes = authCode.scopes || [];
    const accessTokenResult = await issueOAuth2AccessToken(state, user, client, scopes);
    const refreshTokenValue = generateOpaqueToken();
    const refreshExpiresAt = new Date(Date.now() + (client.refreshTokenTTL || state.config.ttls.refreshToken) * 1000);

    await state.storage.sessionRepository.createSession({
        user: user.id, tokenHash: hashOpaqueToken(state, refreshTokenValue), expiresAt: refreshExpiresAt,
        kid: accessTokenResult.kid, jti: accessTokenResult.jti, ipAddress: req.ip, deviceInfo: req.headers['user-agent'], claims: { clientId: client_id, scopes },
    });

    const idToken = scopes.includes('openid') ? await issueIdToken(state, user, client_id, nonce) : null;

    await auditLog(state.logger, state.hooks, 'OAUTH2_TOKEN_ISSUED', { userId: String(user.id), clientId: client_id, grantType: 'authorization_code', scopes });

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
    const { refresh_token, client_id, client_secret } = req.body;
    if (!refresh_token || !client_id) throw new IdpError({ code: 'MISSING_REQUIRED_FIELDS', httpStatus: 400, message: 'refresh_token and client_id are required' });

    const client = await authenticateClient(state, client_id, client_secret);
    assertGrantAllowed(client, GRANT_TYPES.REFRESH_TOKEN);
    const tokenHash = hashOpaqueToken(state, refresh_token);
    const existing = await state.storage.sessionRepository.revokeByRefreshTokenHash(tokenHash);
    if (!existing) throw new IdpError({ code: 'INVALID_REFRESH_TOKEN', httpStatus: 400, message: 'Invalid or expired refresh token' });

    const user = await state.storage.userRepository.findById(existing.user);
    if (!user || user.status !== IDENTITY_STATUS.ACTIVE) throw new IdpError({ code: 'USER_NOT_ACTIVE', httpStatus: 400, message: 'User account is not active' });

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
        kid: accessTokenResult.kid, jti: accessTokenResult.jti, ipAddress: req.ip, deviceInfo: req.headers['user-agent'], claims: existing.claims || {},
    });

    if (existing.jti) await state.cache.set(`${CACHE_KEY_PREFIXES.REVOKED_REFRESH_TOKEN}:${existing.jti}`, '1', state.config.ttls.revocationCache);

    await auditLog(state.logger, state.hooks, 'OAUTH2_TOKEN_ISSUED', { userId: String(user.id), clientId: client_id, grantType: 'refresh_token' });

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
    const { client_id, client_secret, scope } = req.body;
    if (!client_id) throw new IdpError({ code: 'MISSING_REQUIRED_FIELDS', httpStatus: 400, message: 'client_id is required' });

    const client = await authenticateClient(state, client_id, client_secret);
    assertGrantAllowed(client, GRANT_TYPES.CLIENT_CREDENTIALS);

    if (client.clientType !== CLIENT_TYPES.CONFIDENTIAL) {
        throw new IdpError({ code: 'INVALID_REQUEST', httpStatus: 400, message: 'client_credentials requires a confidential client' });
    }

    const allowed = new Set(client.allowedScopes || []);
    const requestedScopes = scope ? scope.split(' ').filter(Boolean) : [...allowed];
    const invalidScopes = requestedScopes.filter((s) => !allowed.has(s));
    if (invalidScopes.length > 0) {
        throw new IdpError({ code: 'INVALID_REQUEST', httpStatus: 400, message: `Requested scopes not allowed: ${invalidScopes.join(', ')}` });
    }

    const accessTokenResult = await issueOAuth2AccessToken(state, { id: client.clientId }, client, requestedScopes);

    await auditLog(state.logger, state.hooks, 'OAUTH2_TOKEN_ISSUED', { clientId: client_id, grantType: 'client_credentials', scopes: requestedScopes });

    res.json({
        access_token: accessTokenResult.token,
        token_type: 'Bearer',
        expires_in: client.accessTokenTTL || state.config.ttls.accessToken,
        scope: requestedScopes.join(' '),
    });
}

/** POST /oauth2/token/revoke — RFC 7009 */
export async function revokeTokenHandler(req, res, next) {
    try {
        const state = getState();
        const { token, client_id, client_secret } = req.body;

        if (client_id) await authenticateClient(state, client_id, client_secret);

        const tokenHash = hashOpaqueToken(state, token);
        const session = await state.storage.sessionRepository.revokeByRefreshTokenHash(tokenHash, { onlyIfActive: false });
        if (session?.jti) await state.cache.set(`${CACHE_KEY_PREFIXES.REVOKED_REFRESH_TOKEN}:${session.jti}`, '1', state.config.ttls.revocationCache);

        await auditLog(state.logger, state.hooks, 'OAUTH2_TOKEN_REVOKED', { clientId: client_id || null });
        res.status(200).json({ status: 'ok' }); // RFC 7009 — always 200, even if token not found
    } catch (err) {
        next(err);
    }
}

/** POST /oauth2/token/introspect — RFC 7662 */
export async function introspectTokenHandler(req, res, next) {
    try {
        const state = getState();
        const { token } = req.body;
        if (!token) return res.json({ active: false });

        const tokenHash = hashOpaqueToken(state, token);
        const session = await state.storage.sessionRepository.findByRefreshTokenHash(tokenHash);
        if (!session || session.revokedAt || session.expiresAt <= new Date()) return res.json({ active: false });

        res.json({
            active: true,
            sub: String(session.user),
            exp: Math.floor(session.expiresAt.getTime() / 1000),
            iat: Math.floor(session.createdAt.getTime() / 1000),
            jti: session.jti,
        });
    } catch (err) {
        next(err);
    }
}
