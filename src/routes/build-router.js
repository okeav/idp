import express from 'express';

import { authContextMiddleware } from '../middleware/auth-context.middleware.js';
import { serviceContextMiddleware } from '../middleware/service-context.middleware.js';
import { validateBody } from '../middleware/validate-body.js';
import { validateQuery } from '../middleware/validate-query.js';

import {
    registerHandler, verifyEmailHandler, resendVerificationEmailHandler,
    loginHandler, refreshTokenHandler, logoutHandler, logoutAllHandler,
    forgotPasswordHandler, resetPasswordHandler, changePasswordHandler,
    getMeHandler, updateMeHandler, deleteMeHandler,
    listSessionsHandler, revokeSessionHandler, revokeAllSessionsHandler,
} from '../password-auth/controllers.js';
import {
    registerSchema, verifyEmailSchema, resendVerificationSchema, loginSchema,
    forgotPasswordSchema, resetPasswordSchema, changePasswordSchema, logoutSchema, updateProfileSchema,
} from '../password-auth/schemas.js';

import { requestMagicLinkHandler, verifyMagicLinkHandler } from '../magic-link/controller.js';
import { requestMagicLinkSchema, verifyMagicLinkSchema } from '../magic-link/schemas.js';

import { generateRegistrationOptionsHandler, verifyRegistrationHandler } from '../webauthn/registration.controller.js';
import { generateAuthenticationOptionsHandler, verifyAuthenticationHandler } from '../webauthn/authentication.controller.js';
import { generateMfaWebauthnChallengeOptionsHandler, verifyMfaWebauthnChallengeHandler } from '../webauthn/mfa.controller.js';
import {
    registrationOptionsSchema, verifyRegistrationSchema, authenticationOptionsSchema,
    verifyAuthenticationSchema, mfaWebauthnOptionsSchema, verifyMfaWebauthnSchema,
} from '../webauthn/schemas.js';

import {
    getMfaStatusHandler, setupMfaHandler, confirmMfaHandler, disableMfaHandler,
    regenerateRecoveryCodesHandler, verifyMfaChallengeHandler,
} from '../mfa/controller.js';
import { confirmMfaSchema, disableMfaSchema, regenerateRecoveryCodesSchema, verifyMfaChallengeSchema } from '../mfa/schemas.js';

import { authorizeHandler, confirmConsentHandler, denyConsentHandler } from '../oauth2/authorize.controller.js';
import { tokenHandler, revokeTokenHandler, introspectTokenHandler } from '../oauth2/token.controller.js';
import { getConsentHandler, listConsentsHandler, revokeConsentHandler } from '../oauth2/consent.controller.js';
import {
    registerOAuthClientHandler, getOAuthClientHandler, listOAuthClientsHandler, updateOAuthClientHandler,
    rotateOAuthClientSecretHandler, deactivateOAuthClientHandler, approveOAuthClientHandler,
} from '../oauth2/client.controller.js';
import {
    authorizeQuerySchema, confirmAuthorizeSchema, denyAuthorizeSchema, tokenSchema, revokeTokenSchema,
    introspectTokenSchema, registerOAuthClientSchema, updateOAuthClientSchema,
} from '../oauth2/schemas.js';

import { userinfoHandler } from '../oidc/userinfo.controller.js';
import { endSessionHandler } from '../oidc/end-session.controller.js';
import { openidConfigurationHandler } from '../oidc/discovery.controller.js';

import { initiateSsoHandler } from '../sso/initiate.controller.js';
import { ssoCallbackHandler } from '../sso/callback.controller.js';
import { ssoInitiateQuerySchema } from '../sso/schemas.js';

import { jwksHandler, authPublicKeyHandler } from '../signing/jwks.controller.js';
import { registerServiceKeyHandler, getServicesJwksHandler } from '../service-mesh/service-key.controller.js';
import { s2sBootstrapMiddleware } from '../service-mesh/s2s-bootstrap.middleware.js';

/**
 * Assembles a fully-wired `express.Router()` covering every route this
 * package implements, using sensible default paths. Entirely optional — if
 * your app wants different paths, custom rate limiting, or to omit a
 * feature (e.g. no OAuth2 authorization-server surface), mount the
 * individual handler exports on your own router instead of calling this.
 *
 * @param {{ ownServiceName?: string }} [opts] - passed through to serviceContextMiddleware
 */
export function buildRouter(opts = {}) {
    const router = express.Router();

    // Password / email identity
    router.post('/register', validateBody(registerSchema), registerHandler);
    router.post('/register/verify-email', validateBody(verifyEmailSchema), verifyEmailHandler);
    router.post('/register/resend-verification', validateBody(resendVerificationSchema), resendVerificationEmailHandler);
    router.post('/login', validateBody(loginSchema), loginHandler);
    router.post('/mfa/verify', validateBody(verifyMfaChallengeSchema), verifyMfaChallengeHandler);
    router.post('/refresh', refreshTokenHandler);
    router.post('/logout', validateBody(logoutSchema), logoutHandler);
    router.post('/logout/all', authContextMiddleware(), logoutAllHandler);
    router.post('/password/forgot', validateBody(forgotPasswordSchema), forgotPasswordHandler);
    router.post('/password/reset', validateBody(resetPasswordSchema), resetPasswordHandler);
    router.post('/password/change', authContextMiddleware(), validateBody(changePasswordSchema), changePasswordHandler);

    // Magic link (passwordless email login)
    router.post('/magic-link/request', validateBody(requestMagicLinkSchema), requestMagicLinkHandler);
    router.post('/magic-link/verify', validateBody(verifyMagicLinkSchema), verifyMagicLinkHandler);

    // Self-service identity ("me")
    router.get('/me', authContextMiddleware(), getMeHandler);
    router.patch('/me', authContextMiddleware(), validateBody(updateProfileSchema), updateMeHandler);
    router.delete('/me', authContextMiddleware(), deleteMeHandler);
    router.get('/me/sessions', authContextMiddleware(), listSessionsHandler);
    router.delete('/me/sessions/:id', authContextMiddleware(), revokeSessionHandler);
    router.delete('/me/sessions', authContextMiddleware(), revokeAllSessionsHandler);

    // MFA
    router.get('/me/mfa', authContextMiddleware(), getMfaStatusHandler);
    router.post('/me/mfa/setup', authContextMiddleware(), setupMfaHandler);
    router.post('/me/mfa/confirm', authContextMiddleware(), validateBody(confirmMfaSchema), confirmMfaHandler);
    router.delete('/me/mfa', authContextMiddleware(), validateBody(disableMfaSchema), disableMfaHandler);
    router.post('/me/mfa/recovery-codes', authContextMiddleware(), validateBody(regenerateRecoveryCodesSchema), regenerateRecoveryCodesHandler);

    // WebAuthn / passkeys — registering a credential always requires an
    // authenticated caller (adding a passkey to an existing account).
    router.post('/webauthn/registration/options', authContextMiddleware(), validateBody(registrationOptionsSchema), generateRegistrationOptionsHandler);
    router.post('/webauthn/registration/verify', authContextMiddleware(), validateBody(verifyRegistrationSchema), verifyRegistrationHandler);

    // Primary passwordless login — no prior auth required.
    router.post('/webauthn/authentication/options', validateBody(authenticationOptionsSchema), generateAuthenticationOptionsHandler);
    router.post('/webauthn/authentication/verify', validateBody(verifyAuthenticationSchema), verifyAuthenticationHandler);

    // Passkey as an MFA second factor — completes the challenge loginHandler
    // issued when user.mfaEnabled, as an alternative to /mfa/verify (TOTP).
    router.post('/webauthn/mfa/options', validateBody(mfaWebauthnOptionsSchema), generateMfaWebauthnChallengeOptionsHandler);
    router.post('/webauthn/mfa/verify', validateBody(verifyMfaWebauthnSchema), verifyMfaWebauthnChallengeHandler);

    // OAuth2 authorization server
    router.get('/oauth2/authorize', validateQuery(authorizeQuerySchema), authContextMiddleware({ optional: true }), authorizeHandler);
    router.post('/oauth2/authorize/confirm', authContextMiddleware(), validateBody(confirmAuthorizeSchema), confirmConsentHandler);
    router.post('/oauth2/authorize/deny', authContextMiddleware(), validateBody(denyAuthorizeSchema), denyConsentHandler);
    router.post('/oauth2/token', validateBody(tokenSchema), tokenHandler);
    router.post('/oauth2/token/revoke', validateBody(revokeTokenSchema), revokeTokenHandler);
    router.post('/oauth2/token/introspect', authContextMiddleware(), validateBody(introspectTokenSchema), introspectTokenHandler);
    router.get('/oauth2/consent', authContextMiddleware(), getConsentHandler);
    router.get('/oauth2/consent/sessions', authContextMiddleware(), listConsentsHandler);
    router.delete('/oauth2/consent/sessions/:clientId', authContextMiddleware(), revokeConsentHandler);

    // OAuth2 client (relying party) management — mount your own admin-auth
    // middleware in front of these in a real app; left unauthenticated here
    // since this package has no admin-role concept of its own (see README).
    router.post('/oauth2/clients', validateBody(registerOAuthClientSchema), registerOAuthClientHandler);
    router.get('/oauth2/clients', listOAuthClientsHandler);
    router.get('/oauth2/clients/:clientId', getOAuthClientHandler);
    router.patch('/oauth2/clients/:clientId', validateBody(updateOAuthClientSchema), updateOAuthClientHandler);
    router.post('/oauth2/clients/:clientId/approve', approveOAuthClientHandler);
    router.post('/oauth2/clients/:clientId/rotate-secret', rotateOAuthClientSecretHandler);
    router.delete('/oauth2/clients/:clientId', deactivateOAuthClientHandler);

    // OIDC
    router.get('/userinfo', authContextMiddleware(), userinfoHandler);
    router.get('/oidc/end-session', authContextMiddleware({ optional: true }), endSessionHandler);
    router.get('/.well-known/openid-configuration', openidConfigurationHandler);

    // SSO
    router.get('/sso/:provider', validateQuery(ssoInitiateQuerySchema), initiateSsoHandler);
    router.get('/sso/:provider/callback', ssoCallbackHandler);
    router.post('/sso/:provider/callback', express.urlencoded({ extended: false }), ssoCallbackHandler);

    // JWKS
    router.get('/.well-known/jwks.json', jwksHandler);
    router.get('/keys/:kid', authPublicKeyHandler);

    // Service mesh (S2S JWKS trust)
    router.post('/internal/service-keys', s2sBootstrapMiddleware, registerServiceKeyHandler);
    router.get('/.well-known/services-jwks.json', getServicesJwksHandler);

    return router;
}

export { serviceContextMiddleware }; // re-exported for building your own protected internal routes alongside this router
