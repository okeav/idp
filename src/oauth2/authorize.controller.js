import crypto from 'crypto';
import { getState } from '../config/state.js';
import { IdpError } from '../errors/idp-error.js';
import { OAUTH_CLIENT_STATUS, CLIENT_TYPES, CACHE_KEY_PREFIXES } from '../config/constants.js';
import { hashOpaqueToken } from '../signing/token.service.js';
import { auditLog } from '../hooks/index.js';

function validateRedirectUri(client, redirectUri) {
    if (!client.redirectUris?.includes(redirectUri)) {
        throw new IdpError({ code: 'INVALID_REDIRECT_URI', httpStatus: 400, message: 'Invalid redirect_uri' });
    }
}

function validateScopes(client, requestedScopes) {
    const allowed = new Set(client.allowedScopes || []);
    const invalid = requestedScopes.filter((s) => !allowed.has(s));
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

/**
 * PKCE is required for public clients always (RFC 9700 §2.1.1), and for every client unless
 * `config.oauth2.requirePkce` is `'public'`: without it a confidential client is still open to
 * authorization-code injection.
 */
function assertPkce(state, client, codeChallenge) {
    const required = client.clientType === CLIENT_TYPES.PUBLIC || state.config.oauth2.requirePkce !== 'public';
    if (required && !codeChallenge) {
        throw new IdpError({ code: 'INVALID_REQUEST', httpStatus: 400, message: 'code_challenge (PKCE, S256) is required' });
    }
}

async function issueAuthorizationCode(state, { clientId, userId, redirectUri, scopes, codeChallenge, nonce, authTime, sessionJti }) {
    const code = crypto.randomBytes(32).toString('hex');
    await state.storage.authorizationCodeRepository.create({
        code: hashOpaqueToken(state, code),
        clientId,
        userId,
        redirectUri,
        scopes,
        codeChallenge: codeChallenge || null,
        codeChallengeMethod: codeChallenge ? 'S256' : null,
        nonce: nonce || null,
        authTime: authTime ? new Date(authTime * 1000) : null,
        // The session that authorized it — revoked before redemption (a sign-out landing while this
        // request was in flight), the code is refused.
        sessionJti: sessionJti ?? null,
        expiresAt: new Date(Date.now() + state.config.ttls.authCode * 1000),
        used: false,
    });
    return code;
}

/** Redirects to the client with the response params plus `iss` (RFC 9207 — lets the client detect a mix-up between authorization servers). */
function redirectToClient(res, state, redirectUri, params) {
    const url = new URL(redirectUri);
    for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== null) url.searchParams.set(k, v);
    url.searchParams.set('iss', state.config.issuer);
    res.redirect(url.toString());
}

const consentKey = (challenge) => `${CACHE_KEY_PREFIXES.OAUTH_CONSENT}:${challenge}`;
const INVALID_CONSENT = () => new IdpError({ code: 'INVALID_CONSENT_CHALLENGE', httpStatus: 400, message: 'Invalid or expired consent challenge — restart authorization' });

/**
 * GET /oauth2/authorize
 *
 * Validates the request. When the user has already consented to every requested scope, issues the
 * code straight away. Otherwise it answers `consent_required` with a `consent_challenge`: the whole
 * validated request is stored server-side under that single-use, user-bound id, and confirm/deny
 * act on exactly that request — never on parameters supplied again at confirm time. That's what
 * stops a forged confirm (CSRF, or a script on a sibling origin) from granting an arbitrary client
 * arbitrary scopes with a redirect of the attacker's choosing: it would need a challenge only the
 * user's own consent page received.
 */
export async function authorizeHandler(req, res, next) {
    try {
        const state = getState();
        const q = req.validatedQuery || req.query;
        const { client_id, redirect_uri, scope, state: oauthState, nonce, code_challenge, response_type } = q;

        if (response_type !== 'code') {
            throw new IdpError({ code: 'INVALID_REQUEST', httpStatus: 400, message: 'Only response_type=code is supported' });
        }

        const client = await loadActiveClient(state, client_id);
        validateRedirectUri(client, redirect_uri);

        const requestedScopes = (scope || 'openid').split(' ').filter(Boolean);
        validateScopes(client, requestedScopes);
        assertPkce(state, client, code_challenge);

        if (!req.auth?.userId) {
            return res.status(401).json({ action: 'login_required' });
        }

        const pending = {
            userId: req.auth.userId, clientId: client_id, redirectUri: redirect_uri, scopes: requestedScopes,
            state: oauthState ?? null, nonce: nonce ?? null, codeChallenge: code_challenge ?? null,
            authTime: req.auth.tokenMeta?.authTime ?? null,
        };

        const existingConsent = await state.storage.consentRepository.find(req.auth.userId, client_id);
        const consentLive = existingConsent && !(existingConsent.expiresAt && new Date(existingConsent.expiresAt) <= new Date());
        const consentedScopes = new Set(consentLive ? existingConsent.scopes || [] : []);
        const missingScopes = requestedScopes.filter((s) => !consentedScopes.has(s));

        if (missingScopes.length > 0) {
            const consentChallenge = crypto.randomBytes(32).toString('base64url');
            await state.cache.set(consentKey(consentChallenge), pending, state.config.ttls.authCode);
            res.set('Cache-Control', 'no-store');
            return res.status(200).json({
                action: 'consent_required',
                consent_challenge: consentChallenge,
                client: { name: client.name, logoUrl: client.logoUrl, websiteUrl: client.websiteUrl, privacyPolicyUrl: client.privacyPolicyUrl },
                scopes: requestedScopes, missingScopes,
            });
        }

        const code = await issueAuthorizationCode(state, { ...pending, sessionJti: req.auth.tokenMeta?.jti });
        await auditLog(state.logger, state.hooks, 'OAUTH2_AUTHORIZE', { userId: req.auth.userId, clientId: client_id, scopes: requestedScopes });
        redirectToClient(res, state, redirect_uri, { code, state: oauthState });
    } catch (err) {
        next(err);
    }
}

/** Redeems a consent challenge — atomically, and only for the user it was issued to. */
async function takePendingAuthorization(state, req) {
    const { consent_challenge: consentChallenge } = req.body;
    if (!req.auth?.userId) throw new IdpError({ code: 'UNAUTHENTICATED', httpStatus: 401, message: 'Authentication required' });
    const pending = await state.cache.take(consentKey(consentChallenge));
    if (!pending || String(pending.userId) !== String(req.auth.userId)) throw INVALID_CONSENT();
    // The client may have been deactivated, or its redirect URIs changed, while the user decided.
    const client = await loadActiveClient(state, pending.clientId);
    validateRedirectUri(client, pending.redirectUri);
    return pending;
}

/** POST /oauth2/authorize/confirm — `{ consent_challenge }` from the authorize response. */
export async function confirmConsentHandler(req, res, next) {
    try {
        const state = getState();
        const pending = await takePendingAuthorization(state, req);

        await state.storage.consentRepository.upsert(req.auth.userId, pending.clientId, pending.scopes);
        const code = await issueAuthorizationCode(state, { ...pending, sessionJti: req.auth.tokenMeta?.jti });

        await auditLog(state.logger, state.hooks, 'OAUTH2_CONSENT_GRANTED', { userId: req.auth.userId, clientId: pending.clientId, scopes: pending.scopes });
        redirectToClient(res, state, pending.redirectUri, { code, state: pending.state });
    } catch (err) {
        next(err);
    }
}

/** POST /oauth2/authorize/deny — `{ consent_challenge }`; redirects back with `error=access_denied`. */
export async function denyConsentHandler(req, res, next) {
    try {
        const state = getState();
        const pending = await takePendingAuthorization(state, req);

        await auditLog(state.logger, state.hooks, 'OAUTH2_CONSENT_DENIED', { userId: req.auth.userId, clientId: pending.clientId });
        redirectToClient(res, state, pending.redirectUri, { error: 'access_denied', error_description: 'The user denied access', state: pending.state });
    } catch (err) {
        next(err);
    }
}

export { loadActiveClient, validateRedirectUri, validateScopes };
