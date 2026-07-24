import crypto from 'crypto';
import { getState } from '../config/state.js';
import { IdpError } from '../errors/idp-error.js';
import { OAUTH_CLIENT_STATUS } from '../config/constants.js';
import { hashOpaqueToken } from '../signing/token.service.js';
import { auditLog } from '../hooks/index.js';

function validateRedirectUri(client, redirectUri) {
    if (!client.redirectUris?.includes(redirectUri)) {
        throw new IdpError({ code: 'INVALID_REDIRECT_URI', httpStatus: 400, message: 'Invalid redirect_uri' });
    }
}

function validateScopes(client, requestedScopes) {
    const allowed = new Set(client.allowedScopes || []);
    const invalid = requestedScopes.filter((s) => !allowed.has(s) && s !== 'openid');
    if (invalid.length > 0) {
        throw new IdpError({ code: 'INVALID_REQUEST', httpStatus: 400, message: `Requested scopes not allowed: ${invalid.join(', ')}` });
    }
}

async function loadActiveClient(state, clientId) {
    const client = await state.storage.oauthClientRepository.findByClientId(clientId);
    if (!client || client.status !== OAUTH_CLIENT_STATUS.ACTIVE) {
        throw new IdpError({ code: 'OAUTH_CLIENT_NOT_FOUND', httpStatus: 400, message: 'Unknown or inactive client' });
    }
    return client;
}

async function issueAuthorizationCode(state, { clientId, userId, redirectUri, scopes, codeChallenge, codeChallengeMethod }) {
    const code = crypto.randomBytes(32).toString('hex');
    const codeHash = hashOpaqueToken(state, code);
    await state.storage.authorizationCodeRepository.create({
        code: codeHash,
        clientId,
        userId,
        redirectUri,
        scopes,
        codeChallenge: codeChallenge || null,
        codeChallengeMethod: codeChallengeMethod || null,
        expiresAt: new Date(Date.now() + state.config.ttls.authCode * 1000),
        used: false,
    });
    return code;
}

/** GET /oauth2/authorize */
export async function authorizeHandler(req, res, next) {
    try {
        const state = getState();
        const q = req.validatedQuery || req.query;
        const { client_id, redirect_uri, scope, state: oauthState, code_challenge, code_challenge_method, response_type } = q;

        if (response_type !== 'code') {
            throw new IdpError({ code: 'INVALID_REQUEST', httpStatus: 400, message: 'Only response_type=code is supported' });
        }

        const client = await loadActiveClient(state, client_id);
        validateRedirectUri(client, redirect_uri);

        const requestedScopes = (scope || 'openid').split(' ').filter(Boolean);
        validateScopes(client, requestedScopes);

        if (!req.auth?.userId) {
            return res.status(401).json({
                action: 'login_required',
                client_id, redirect_uri, scope, state: oauthState, code_challenge, code_challenge_method, response_type,
            });
        }

        const existingConsent = await state.storage.consentRepository.find(req.auth.userId, client_id);
        const consentedScopes = new Set(existingConsent?.scopes || []);
        const missingScopes = requestedScopes.filter((s) => !consentedScopes.has(s));

        if (missingScopes.length > 0) {
            return res.status(200).json({
                action: 'consent_required',
                client: { name: client.name, logoUrl: client.logoUrl, websiteUrl: client.websiteUrl, privacyPolicyUrl: client.privacyPolicyUrl },
                scopes: requestedScopes, missingScopes,
                client_id, redirect_uri, scope, state: oauthState, code_challenge, code_challenge_method,
            });
        }

        const code = await issueAuthorizationCode(state, { clientId: client_id, userId: req.auth.userId, redirectUri: redirect_uri, scopes: requestedScopes, codeChallenge: code_challenge, codeChallengeMethod: code_challenge_method });

        await auditLog(state.logger, state.hooks, 'OAUTH2_AUTHORIZE', { userId: req.auth.userId, clientId: client_id, scopes: requestedScopes });

        const redirectUrl = new URL(redirect_uri);
        redirectUrl.searchParams.set('code', code);
        if (oauthState) redirectUrl.searchParams.set('state', oauthState);
        res.redirect(redirectUrl.toString());
    } catch (err) {
        next(err);
    }
}

/** POST /oauth2/authorize/confirm */
export async function confirmConsentHandler(req, res, next) {
    try {
        const state = getState();
        const { client_id, redirect_uri, scope, state: oauthState, code_challenge, code_challenge_method } = req.body;

        const client = await loadActiveClient(state, client_id);
        validateRedirectUri(client, redirect_uri);

        if (!req.auth?.userId) throw new IdpError({ code: 'UNAUTHENTICATED', httpStatus: 401, message: 'Authentication required' });

        const requestedScopes = (scope || 'openid').split(' ').filter(Boolean);
        validateScopes(client, requestedScopes);

        await state.storage.consentRepository.upsert(req.auth.userId, client_id, requestedScopes);
        const code = await issueAuthorizationCode(state, { clientId: client_id, userId: req.auth.userId, redirectUri: redirect_uri, scopes: requestedScopes, codeChallenge: code_challenge, codeChallengeMethod: code_challenge_method });

        await auditLog(state.logger, state.hooks, 'OAUTH2_CONSENT_GRANTED', { userId: req.auth.userId, clientId: client_id, scopes: requestedScopes });

        const redirectUrl = new URL(redirect_uri);
        redirectUrl.searchParams.set('code', code);
        if (oauthState) redirectUrl.searchParams.set('state', oauthState);
        res.redirect(redirectUrl.toString());
    } catch (err) {
        next(err);
    }
}

/** POST /oauth2/authorize/deny */
export async function denyConsentHandler(req, res, next) {
    try {
        const state = getState();
        const { redirect_uri, state: oauthState, client_id } = req.body;

        await auditLog(state.logger, state.hooks, 'OAUTH2_CONSENT_DENIED', { userId: req.auth?.userId, clientId: client_id });

        const redirectUrl = new URL(redirect_uri);
        redirectUrl.searchParams.set('error', 'access_denied');
        redirectUrl.searchParams.set('error_description', 'The user denied access');
        if (oauthState) redirectUrl.searchParams.set('state', oauthState);
        res.redirect(redirectUrl.toString());
    } catch (err) {
        next(err);
    }
}

export { loadActiveClient, validateRedirectUri, validateScopes };
