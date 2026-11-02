import crypto from 'crypto';
import { getState } from '../config/state.js';
import { IdpError } from '../errors/idp-error.js';
import { CACHE_KEY_PREFIXES } from '../config/constants.js';
import { buildSsoProviders, isAllowedRedirectUri } from './providers.js';
import { auditLog } from '../hooks/index.js';
import { enforceRateLimit } from '../rate-limit/enforce.js';
import { ssoBindingCookie } from './binding.js';

const RESERVED_QUERY_KEYS = new Set(['redirect_uri']);
const MAX_EXTRA_KEYS = 10;
const MAX_EXTRA_KEY_LENGTH = 64;
const MAX_EXTRA_VALUE_LENGTH = 256;

/**
 * Extra query params beyond `redirect_uri` are opaque, consumer-defined context (e.g. an intended-role
 * hint) handed to `resolveAuthContext` at callback time. They come from whoever built the link, so
 * they are UNTRUSTED input — and they sit in the cache for the whole login. Only short string values
 * are kept (at most 10); anything else (nested objects from Express 4's qs parser, long values) is
 * dropped.
 */
function sanitizeExtra(query) {
    const extra = {};
    for (const [k, v] of Object.entries(query)) {
        if (RESERVED_QUERY_KEYS.has(k) || Object.keys(extra).length >= MAX_EXTRA_KEYS) continue;
        if (k.length > MAX_EXTRA_KEY_LENGTH || typeof v !== 'string' || v.length > MAX_EXTRA_VALUE_LENGTH) continue;
        extra[k] = v;
    }
    return extra;
}

const sha256b64url = (s) => crypto.createHash('sha256').update(s).digest('base64url');

/**
 * GET /sso/:provider
 *
 * Starts a provider login. Alongside the random `state`, it sets a cookie (one per attempt) holding a
 * random binding value whose hash is stored with the state: the callback only completes in the
 * browser that started the login. Without that, an attacker could start a login with their own
 * provider account and get a victim's browser to finish it — signing the victim into the
 * attacker's account (login CSRF). With providers that support it, the code exchange is also bound
 * by PKCE; Apple (id_token-based) is bound by a nonce.
 */
export async function initiateSsoHandler(req, res, next) {
    try {
        const state = getState();
        await enforceRateLimit(state, `sso-initiate:ip:${req.ip}`, state.config.rateLimiting.ssoInitiate, { failMode: 'closed' });

        const { provider } = req.params;
        const q = req.validatedQuery || req.query;
        const { redirect_uri } = q;

        if (!redirect_uri || !isAllowedRedirectUri(state.config, redirect_uri)) {
            throw new IdpError({ code: 'INVALID_REDIRECT_URI', httpStatus: 400, message: 'redirect_uri is missing or not on an allowed origin' });
        }

        const providers = buildSsoProviders(state.config);
        const providerConfig = providers[provider];
        if (!providerConfig) throw new IdpError({ code: 'INVALID_SSO_PROVIDER', httpStatus: 400, message: `Unknown or unconfigured SSO provider: ${provider}` });

        const csrfState = crypto.randomBytes(32).toString('base64url');
        const binding = crypto.randomBytes(32).toString('base64url');
        const codeVerifier = providerConfig.pkce ? crypto.randomBytes(32).toString('base64url') : null;
        const nonce = providerConfig.nonce ? crypto.randomBytes(16).toString('base64url') : null;

        await state.cache.set(`${CACHE_KEY_PREFIXES.SSO_STATE}:${csrfState}`, {
            provider, redirect_uri, extra: sanitizeExtra(q), bindingHash: sha256b64url(binding), codeVerifier, nonce,
        }, state.config.ttls.ssoState);

        const cookie = ssoBindingCookie(state, csrfState, providerConfig);
        res.cookie(cookie.name, binding, cookie.options);

        const params = new URLSearchParams({
            response_type: 'code',
            client_id: providerConfig.clientId,
            redirect_uri: providerConfig.redirectUri,
            scope: providerConfig.scopes.join(' '),
            state: csrfState,
            ...(codeVerifier ? { code_challenge: sha256b64url(codeVerifier), code_challenge_method: 'S256' } : {}),
            ...(nonce ? { nonce } : {}),
            ...(providerConfig.name === 'apple' ? { response_mode: 'form_post' } : {}),
            ...(providerConfig.name === 'google' ? { access_type: 'online', prompt: 'select_account' } : {}),
        });

        await auditLog(state.logger, state.hooks, 'SSO_INITIATED', { provider });
        res.redirect(`${providerConfig.authorizationUrl}?${params.toString()}`);
    } catch (err) {
        next(err);
    }
}
