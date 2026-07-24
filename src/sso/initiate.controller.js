import crypto from 'crypto';
import { getState } from '../config/state.js';
import { IdpError } from '../errors/idp-error.js';
import { CACHE_KEY_PREFIXES } from '../config/constants.js';
import { buildSsoProviders, isAllowedRedirectUri } from './providers.js';
import { auditLog } from '../hooks/index.js';

const RESERVED_QUERY_KEYS = new Set(['redirect_uri']);

/** GET /sso/:provider */
export async function initiateSsoHandler(req, res, next) {
    try {
        const state = getState();
        const { provider } = req.params;
        const q = req.validatedQuery || req.query;
        const { redirect_uri } = q;

        if (!redirect_uri || !isAllowedRedirectUri(state.config, redirect_uri)) {
            throw new IdpError({ code: 'INVALID_REDIRECT_URI', httpStatus: 400, message: 'redirect_uri is missing or not on an allowed origin' });
        }

        const providers = buildSsoProviders(state.config);
        const providerConfig = providers[provider];
        if (!providerConfig) throw new IdpError({ code: 'INVALID_SSO_PROVIDER', httpStatus: 400, message: `Unknown or unconfigured SSO provider: ${provider}` });

        // Extra query params beyond `redirect_uri` are opaque, consumer-defined
        // context (e.g. an intended-role hint) — cached alongside the CSRF
        // state and handed back to the `resolveAuthContext` hook at callback
        // time. This package never interprets them.
        const extra = {};
        for (const [k, v] of Object.entries(q)) {
            if (!RESERVED_QUERY_KEYS.has(k)) extra[k] = v;
        }

        const csrfState = crypto.randomBytes(20).toString('hex');
        await state.cache.set(`${CACHE_KEY_PREFIXES.SSO_STATE}:${csrfState}`, { provider, redirect_uri, extra }, state.config.ttls.ssoState);

        const params = new URLSearchParams({
            response_type: 'code',
            client_id: providerConfig.clientId,
            redirect_uri: providerConfig.redirectUri,
            scope: providerConfig.scopes.join(' '),
            state: csrfState,
            ...(providerConfig.name === 'apple' ? { response_mode: 'form_post' } : {}),
            ...(providerConfig.name === 'google' ? { access_type: 'online', prompt: 'select_account' } : {}),
        });

        await auditLog(state.logger, state.hooks, 'SSO_INITIATED', { provider });
        res.redirect(`${providerConfig.authorizationUrl}?${params.toString()}`);
    } catch (err) {
        next(err);
    }
}
