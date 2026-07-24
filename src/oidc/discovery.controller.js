import { getState } from '../config/state.js';

/** GET /.well-known/openid-configuration */
export function openidConfigurationHandler(req, res) {
    const state = getState();
    const issuer = state.config.issuer;

    res.set('Cache-Control', `public, max-age=${state.config.ttls.discoveryCache}`).json({
        issuer,
        authorization_endpoint: `${issuer}/oauth2/authorize`,
        token_endpoint: `${issuer}/oauth2/token`,
        userinfo_endpoint: `${issuer}/userinfo`,
        jwks_uri: `${issuer}/.well-known/jwks.json`,
        end_session_endpoint: `${issuer}/oidc/end-session`,
        revocation_endpoint: `${issuer}/oauth2/token/revoke`,
        introspection_endpoint: `${issuer}/oauth2/token/introspect`,
        response_types_supported: ['code'],
        grant_types_supported: ['authorization_code', 'refresh_token'],
        subject_types_supported: ['public'],
        id_token_signing_alg_values_supported: ['RS256'],
        token_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic'],
        scopes_supported: ['openid', 'email', 'profile'],
        claims_supported: [
            'sub', 'iss', 'aud', 'exp', 'iat', 'jti', 'nonce',
            'email', 'email_verified',
            'name', 'given_name', 'family_name', 'picture', 'locale', 'zoneinfo', 'updated_at',
        ],
        code_challenge_methods_supported: ['S256', 'plain'],
        request_parameter_supported: false,
        claims_parameter_supported: false,
    });
}
