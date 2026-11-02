import crypto from 'crypto';
import { getState } from '../config/state.js';
import { IdpError } from '../errors/idp-error.js';
import { OAUTH_CLIENT_STATUS, CLIENT_TYPES, CACHE_KEY_PREFIXES } from '../config/constants.js';
import { hashOpaqueToken, HASH_PURPOSES } from '../signing/token.service.js';
import { auditLog } from '../hooks/index.js';
import { currentSessionEpoch } from '../utils/session-family.js';

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

async function issueAuthorizationCode(state, { clientId, userId, redirectUri, scopes, codeChallenge, nonce, authTime, sessionJti, consentVersion }) {
    const code = crypto.randomBytes(32).toString('hex');
    const sessionEpoch = await currentSessionEpoch(state, userId);
    await state.storage.authorizationCodeRepository.create({
        code: hashOpaqueToken(state, code, HASH_PURPOSES.AUTHORIZATION_CODE),
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
        // Redemption refuses the code if the user's sessions were revoked, or the consent changed, since.
        sessionEpoch,
        consentVersion: consentVersion ?? 0,
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

const PROMPT_VALUES = new Set(['none', 'login', 'consent', 'select_account']);

/**
 * How long a login still counts as "just now" for `prompt=login` / `max_age=0`: the user signs in
 * on the IdP's page, which then repeats the authorize request — that repeat must find the new login
 * fresh, not ask for another one.
 */
export const FRESH_LOGIN_SECONDS = 60;

/**
 * `prompt` and `max_age` (OIDC Core §3.1.2.1). Unknown prompt values, or `none` with another, are
 * refused. `select_account` is treated as `login` (there is no account chooser: signing in again is
 * how the user picks an account). `max_age=0` means `prompt=login`.
 */
function resolvePrompt(q) {
    const values = new Set(String(q.prompt ?? '').split(' ').filter(Boolean));
    for (const v of values) {
        if (!PROMPT_VALUES.has(v)) throw new IdpError({ code: 'INVALID_REQUEST', httpStatus: 400, message: `Unsupported prompt value: ${v}` });
    }
    if (values.has('none') && values.size > 1) throw new IdpError({ code: 'INVALID_REQUEST', httpStatus: 400, message: 'prompt=none cannot be combined with other values' });
    const maxAge = q.max_age === undefined ? undefined : Number(q.max_age);
    return {
        none: values.has('none'),
        login: values.has('login') || values.has('select_account') || maxAge === 0,
        consent: values.has('consent'),
        maxAge: maxAge === 0 ? undefined : maxAge,
    };
}

/** Why the request needs a (new) login, or null: not signed in, or the login is older than prompt/max_age allow. */
function loginRequiredReason(req, prompt) {
    if (!req.auth?.userId) return 'unauthenticated';
    const authTime = req.auth.tokenMeta?.authTime;
    const age = Number.isInteger(authTime) ? Math.floor(Date.now() / 1000) - authTime : Infinity;
    if (prompt.login && !(age <= FRESH_LOGIN_SECONDS)) return 'prompt_login';
    if (prompt.maxAge !== undefined && !(age <= prompt.maxAge)) return 'max_age';
    return null;
}

/** The session behind the request's token — none for a sessionless token (the public issueAccessToken export). */
const sessionJtiOf = (req) => (req.auth?.tokenMeta?.sessionless ? null : req.auth?.tokenMeta?.jti ?? null);

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
        if (requestedScopes.length === 0) throw new IdpError({ code: 'INVALID_REQUEST', httpStatus: 400, message: 'scope must name at least one scope' });
        validateScopes(client, requestedScopes);
        assertPkce(state, client, code_challenge);

        const prompt = resolvePrompt(q);
        const loginReason = loginRequiredReason(req, prompt);
        if (loginReason) {
            // prompt=none: the client asked for no UI, so the answer goes back to it (redirect_uri is validated).
            if (prompt.none) return redirectToClient(res, state, redirect_uri, { error: 'login_required', state: oauthState });
            return res.status(401).json({ action: 'login_required', reason: loginReason });
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

        if (missingScopes.length > 0 || prompt.consent) {
            if (prompt.none) return redirectToClient(res, state, redirect_uri, { error: 'consent_required', state: oauthState });
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

        const code = await issueAuthorizationCode(state, { ...pending, sessionJti: sessionJtiOf(req), consentVersion: existingConsent?.version });
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

        const consent = await state.storage.consentRepository.upsert(req.auth.userId, pending.clientId, pending.scopes);
        const code = await issueAuthorizationCode(state, { ...pending, sessionJti: sessionJtiOf(req), consentVersion: consent?.version });

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
