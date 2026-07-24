import { IdpError } from '../errors/idp-error.js';

/**
 * WebAuthn is opt-in — `config.webauthn` isn't validated at
 * `initIdentityProvider()` time so consumers who don't use passkeys never
 * need to think about it. Validated lazily, here, on first actual use.
 *
 * `rpID` must be the **frontend's** registrable domain (the origin that
 * calls `navigator.credentials.create()/.get()`), which is not necessarily
 * this API's own hostname if the API is deployed on a subdomain like
 * `api.example.com` serving a frontend at `example.com` — the RP ID must be
 * the common parent (`example.com`) in that case.
 */
export function getWebauthnConfig(state) {
    const cfg = state.config.webauthn || {};
    if (!cfg.rpID || !cfg.rpName || !cfg.origin) {
        throw new IdpError({
            code: 'WEBAUTHN_NOT_CONFIGURED',
            httpStatus: 500,
            message: 'config.webauthn.{rpID, rpName, origin} must be set to use passkey/WebAuthn endpoints. ' +
                'rpID is the frontend\'s registrable domain (not necessarily this API\'s own host); origin is the frontend\'s full URL (or an array of allowed origins).',
        });
    }
    return cfg;
}
