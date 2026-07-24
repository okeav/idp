import { getState } from './config/state.js';
import * as tokenService from './signing/token.service.js';

// ── Bootstrap ────────────────────────────────────────────────────────────
export { initIdentityProvider } from './config/init.js';
export { configFromEnv } from './config/from-env.js';

// ── Errors ───────────────────────────────────────────────────────────────
export { IdpError, isIdpError } from './errors/idp-error.js';
export { ERROR_CODES } from './errors/error-codes.js';

// ── Token issuance / verification (RS256) ───────────────────────────────
// Thin wrappers over signing/token.service.js that inject the singleton
// state, so the public signatures match the design doc exactly — no
// internal state object leaks into the public API.
export async function issueAccessToken(input, opts) {
    return tokenService.issueAccessToken(getState(), input, opts);
}
export async function verifyAccessToken(token, opts) {
    return tokenService.verifyAccessToken(getState(), token, opts);
}
export async function issueIdToken(user, audience, nonce) {
    return tokenService.issueIdToken(getState(), user, audience, nonce);
}
export async function issueOAuth2AccessToken(subject, client, scopes) {
    return tokenService.issueOAuth2AccessToken(getState(), subject, client, scopes);
}
export async function issueMfaChallengeToken(subjectId) {
    return tokenService.issueMfaChallengeToken(getState(), subjectId);
}
export function verifyMfaChallengeToken(token) {
    return tokenService.verifyMfaChallengeToken(getState(), token);
}
export function verifyIssuedToken(token, opts) {
    return tokenService.verifyIssuedToken(getState(), token, opts);
}

// ── JWKS / discovery (own user-token keys) ──────────────────────────────
export { jwksHandler, authPublicKeyHandler } from './signing/jwks.controller.js';
export { openidConfigurationHandler } from './oidc/discovery.controller.js';

// ── Service mesh — S2S JWKS trust (kept in scope as a differentiator) ──
export { registerServiceKeyHandler, getServicesJwksHandler } from './service-mesh/service-key.controller.js';
export { s2sBootstrapMiddleware } from './service-mesh/s2s-bootstrap.middleware.js';
export {
    initServiceIdentity,
    mintServiceToken,
    mintServiceToken as issueServiceToken,
    getServiceIdentity,
    verifyServiceTokenRemote,
} from './service-mesh/service-identity.client.js';

// ── Middleware ───────────────────────────────────────────────────────────
export { authContextMiddleware } from './middleware/auth-context.middleware.js';
export { serviceContextMiddleware } from './middleware/service-context.middleware.js';
export { requireServiceCallerMiddleware } from './middleware/require-service-caller.middleware.js';
export { validateBody } from './middleware/validate-body.js';
export { validateQuery } from './middleware/validate-query.js';
export { cookieParser } from './middleware/cookie-parser.js';

// ── Password / email identity flows ─────────────────────────────────────
export {
    registerHandler,
    verifyEmailHandler,
    resendVerificationEmailHandler,
    loginHandler,
    refreshTokenHandler,
    logoutHandler,
    logoutAllHandler,
    forgotPasswordHandler,
    resetPasswordHandler,
    changePasswordHandler,
    getMeHandler,
    updateMeHandler,
    deleteMeHandler,
    listSessionsHandler,
    revokeSessionHandler,
    revokeAllSessionsHandler,
} from './password-auth/controllers.js';

// ── MFA ──────────────────────────────────────────────────────────────────
export {
    getMfaStatusHandler,
    setupMfaHandler,
    confirmMfaHandler,
    disableMfaHandler,
    regenerateRecoveryCodesHandler,
    verifyMfaChallengeHandler,
} from './mfa/controller.js';

// ── OAuth2 authorization server + OIDC ───────────────────────────────────
export {
    registerOAuthClientHandler,
    getOAuthClientHandler,
    listOAuthClientsHandler,
    updateOAuthClientHandler,
    rotateOAuthClientSecretHandler,
    deactivateOAuthClientHandler,
    approveOAuthClientHandler,
} from './oauth2/client.controller.js';
export { authorizeHandler, confirmConsentHandler, denyConsentHandler } from './oauth2/authorize.controller.js';
export { tokenHandler, revokeTokenHandler, introspectTokenHandler } from './oauth2/token.controller.js';
export { getConsentHandler, listConsentsHandler, revokeConsentHandler } from './oauth2/consent.controller.js';
export { userinfoHandler } from './oidc/userinfo.controller.js';
export { endSessionHandler } from './oidc/end-session.controller.js';

// ── SSO (social login) — single-step ─────────────────────────────────────
export { initiateSsoHandler } from './sso/initiate.controller.js';
export { ssoCallbackHandler } from './sso/callback.controller.js';

// ── Magic link (passwordless email login) ───────────────────────────────
export { requestMagicLinkHandler, verifyMagicLinkHandler } from './magic-link/controller.js';

// ── WebAuthn / passkeys ──────────────────────────────────────────────────
export { generateRegistrationOptionsHandler, verifyRegistrationHandler } from './webauthn/registration.controller.js';
export { generateAuthenticationOptionsHandler, verifyAuthenticationHandler } from './webauthn/authentication.controller.js';
export { generateMfaWebauthnChallengeOptionsHandler, verifyMfaWebauthnChallengeHandler } from './webauthn/mfa.controller.js';

// ── Cache adapters (advanced — most consumers just use config.cache) ────
export { MemoryCacheAdapter } from './cache/memory.adapter.js';
export { RedisCacheAdapter, createRedisCacheAdapter } from './cache/redis.adapter.js';

// ── Rate limiter adapters (advanced — most consumers just use config.rateLimiting) ──
export { MemoryRateLimiter } from './rate-limit/memory.adapter.js';
export { RedisRateLimiter, createRedisRateLimiter } from './rate-limit/redis.adapter.js';
export { NoopRateLimiter } from './rate-limit/noop.adapter.js';

// ── Outbound webhooks (advanced — most consumers just use config.webhooks) ──
export { WebhookDispatcher } from './webhooks/dispatcher.js';
export { verifyWebhookSignature } from './webhooks/sign.js';

// ── Request-validation schemas (zod) — reuse or extend in your own routes ──
import * as passwordAuthSchemas from './password-auth/schemas.js';
import * as mfaSchemas from './mfa/schemas.js';
import * as oauth2Schemas from './oauth2/schemas.js';
import * as ssoSchemas from './sso/schemas.js';
import * as magicLinkSchemas from './magic-link/schemas.js';
import * as webauthnSchemas from './webauthn/schemas.js';
export const schemas = { ...passwordAuthSchemas, ...mfaSchemas, ...oauth2Schemas, ...ssoSchemas, ...magicLinkSchemas, ...webauthnSchemas };

// ── Optional convenience: a fully-wired express.Router() ────────────────
export { buildRouter } from './routes/build-router.js';
