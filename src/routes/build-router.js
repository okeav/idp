import express from 'express';

import { authContextMiddleware } from '../middleware/auth-context.middleware.js';
import { requireRecentAuth } from '../middleware/require-recent-auth.middleware.js';
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
    forgotPasswordSchema, resetPasswordSchema, changePasswordSchema, logoutSchema, refreshSchema, updateProfileSchema,
} from '../password-auth/schemas.js';

import { requestMagicLinkHandler, verifyMagicLinkHandler } from '../magic-link/controller.js';
import { requestMagicLinkSchema, verifyMagicLinkSchema } from '../magic-link/schemas.js';

import { generateRegistrationOptionsHandler, verifyRegistrationHandler, listPasskeysHandler, deletePasskeyHandler } from '../webauthn/registration.controller.js';
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
    introspectTokenSchema, registerOAuthClientSchema, updateOAuthClientSchema, consentQuerySchema,
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

const FEATURE_NAMES = ['magicLink', 'webauthn', 'sso', 'oauth2', 'oidc', 'serviceMesh'];

/**
 * Assembles a fully-wired `express.Router()` covering the routes this
 * package implements, using sensible default paths. Entirely optional — if
 * your app wants different paths or custom rate limiting, mount the
 * individual handler exports on your own router instead of calling this.
 *
 * @param {object} [opts]
 * @param {{ middleware: import('express').RequestHandler | import('express').RequestHandler[] }} [opts.clientManagement]
 *   OAuth2 client (relying-party) administration — register, list, get,
 *   update, approve, rotate-secret, deactivate under `/oauth2/clients`. NOT
 *   mounted unless this is given, because this package has no admin-role
 *   concept of its own: you supply the admin authentication/authorization as
 *   `middleware`, which runs before every one of those routes. At least one
 *   middleware is required — passing `clientManagement` without any throws.
 * @param {Partial<Record<'magicLink'|'webauthn'|'sso'|'oauth2'|'oidc'|'serviceMesh', boolean>>} [opts.features]
 *   Set a surface to `false` to leave its routes unmounted. Everything
 *   defaults to `true` (mounted).
 */
export function buildRouter(opts = {}) {
    const features = resolveFeatures(opts.features);
    const clientManagementMiddleware = resolveClientManagement(opts.clientManagement);
    const router = express.Router();

    // Every response here may carry tokens, codes or account data: never cache it. Discovery and
    // JWKS handlers set their own (public) Cache-Control, overriding this.
    router.use((_req, res, next) => {
        res.set('Cache-Control', 'no-store');
        next();
    });

    // Password / email identity
    router.post('/register', validateBody(registerSchema), registerHandler);
    router.post('/register/verify-email', validateBody(verifyEmailSchema), verifyEmailHandler);
    router.post('/register/resend-verification', validateBody(resendVerificationSchema), resendVerificationEmailHandler);
    router.post('/login', validateBody(loginSchema), loginHandler);
    router.post('/mfa/verify', validateBody(verifyMfaChallengeSchema), verifyMfaChallengeHandler);
    router.post('/refresh', validateBody(refreshSchema), refreshTokenHandler);
    router.post('/logout', validateBody(logoutSchema), logoutHandler); // refreshToken in the body OR the httpOnly cookie
    router.post('/logout/all', authContextMiddleware(), logoutAllHandler);
    router.post('/password/forgot', validateBody(forgotPasswordSchema), forgotPasswordHandler);
    router.post('/password/reset', validateBody(resetPasswordSchema), resetPasswordHandler);
    router.post('/password/change', authContextMiddleware(), validateBody(changePasswordSchema), changePasswordHandler);

    // Magic link (passwordless email login)
    if (features.magicLink) {
        router.post('/magic-link/request', validateBody(requestMagicLinkSchema), requestMagicLinkHandler);
        router.post('/magic-link/verify', validateBody(verifyMagicLinkSchema), verifyMagicLinkHandler);
    }

    // Self-service identity ("me")
    router.get('/me', authContextMiddleware(), getMeHandler);
    router.patch('/me', authContextMiddleware(), validateBody(updateProfileSchema), updateMeHandler);
    router.delete('/me', authContextMiddleware(), requireRecentAuth(), deleteMeHandler);
    router.get('/me/sessions', authContextMiddleware(), listSessionsHandler);
    router.delete('/me/sessions/:id', authContextMiddleware(), revokeSessionHandler);
    router.delete('/me/sessions', authContextMiddleware(), revokeAllSessionsHandler);

    // MFA
    router.get('/me/mfa', authContextMiddleware(), getMfaStatusHandler);
    // Enrolling a second factor requires a recent login: otherwise a stolen session could enrol
    // the attacker's authenticator on an account that has none, locking the owner out.
    router.post('/me/mfa/setup', authContextMiddleware(), requireRecentAuth(), setupMfaHandler);
    router.post('/me/mfa/confirm', authContextMiddleware(), requireRecentAuth(), validateBody(confirmMfaSchema), confirmMfaHandler);
    router.delete('/me/mfa', authContextMiddleware(), validateBody(disableMfaSchema), disableMfaHandler);
    router.post('/me/mfa/recovery-codes', authContextMiddleware(), validateBody(regenerateRecoveryCodesSchema), regenerateRecoveryCodesHandler);

    if (features.webauthn) {
        // WebAuthn / passkeys — registering a credential requires an authenticated caller who
        // logged in recently: a passkey is a permanent login, so a stolen session must not be
        // able to add one.
        router.post('/webauthn/registration/options', authContextMiddleware(), requireRecentAuth(), validateBody(registrationOptionsSchema), generateRegistrationOptionsHandler);
        router.post('/webauthn/registration/verify', authContextMiddleware(), requireRecentAuth(), validateBody(verifyRegistrationSchema), verifyRegistrationHandler);
        router.get('/me/passkeys', authContextMiddleware(), listPasskeysHandler);
        router.delete('/me/passkeys/:credentialId', authContextMiddleware(), requireRecentAuth(), deletePasskeyHandler);

        // Primary passwordless login — no prior auth required.
        router.post('/webauthn/authentication/options', validateBody(authenticationOptionsSchema), generateAuthenticationOptionsHandler);
        router.post('/webauthn/authentication/verify', validateBody(verifyAuthenticationSchema), verifyAuthenticationHandler);

        // Passkey as an MFA second factor — completes the challenge loginHandler
        // issued when user.mfaEnabled, as an alternative to /mfa/verify (TOTP).
        router.post('/webauthn/mfa/options', validateBody(mfaWebauthnOptionsSchema), generateMfaWebauthnChallengeOptionsHandler);
        router.post('/webauthn/mfa/verify', validateBody(verifyMfaWebauthnSchema), verifyMfaWebauthnChallengeHandler);
    }

    // OAuth2 authorization server
    if (features.oauth2) {
        router.get('/oauth2/authorize', validateQuery(authorizeQuerySchema), authContextMiddleware({ optional: true }), authorizeHandler);
        router.post('/oauth2/authorize/confirm', authContextMiddleware(), validateBody(confirmAuthorizeSchema), confirmConsentHandler);
        router.post('/oauth2/authorize/deny', authContextMiddleware(), validateBody(denyAuthorizeSchema), denyConsentHandler);
        router.post('/oauth2/token', validateBody(tokenSchema), tokenHandler);
        router.post('/oauth2/token/revoke', validateBody(revokeTokenSchema), revokeTokenHandler);
        // Revoke and introspect authenticate the calling client (RFC 7009 / RFC 7662), not a user.
        router.post('/oauth2/token/introspect', validateBody(introspectTokenSchema), introspectTokenHandler);
        router.get('/oauth2/consent', authContextMiddleware(), validateQuery(consentQuerySchema), getConsentHandler);
        router.get('/oauth2/consent/sessions', authContextMiddleware(), listConsentsHandler);
        router.delete('/oauth2/consent/sessions/:clientId', authContextMiddleware(), revokeConsentHandler);
    }

    // OAuth2 client (relying party) management — only behind the caller's
    // own admin middleware, never by default. Every route lives on a
    // sub-router whose first handlers are that middleware, so nothing under
    // /oauth2/clients is reachable without passing it.
    if (clientManagementMiddleware) {
        const clients = express.Router();
        clients.use(...clientManagementMiddleware);
        clients.post('/', validateBody(registerOAuthClientSchema), registerOAuthClientHandler);
        clients.get('/', listOAuthClientsHandler);
        clients.get('/:clientId', getOAuthClientHandler);
        clients.patch('/:clientId', validateBody(updateOAuthClientSchema), updateOAuthClientHandler);
        clients.post('/:clientId/approve', approveOAuthClientHandler);
        clients.post('/:clientId/rotate-secret', rotateOAuthClientSecretHandler);
        clients.delete('/:clientId', deactivateOAuthClientHandler);
        router.use('/oauth2/clients', clients);
    }

    // OIDC
    if (features.oidc) {
        // The one IdP route a relying party calls with the access token it was issued.
        router.get('/userinfo', authContextMiddleware({ accept: ['oauth2-user'] }), userinfoHandler);
        router.get('/oidc/end-session', authContextMiddleware({ optional: true }), endSessionHandler);
        router.get('/.well-known/openid-configuration', openidConfigurationHandler);
    }

    // SSO
    if (features.sso) {
        router.get('/sso/:provider', validateQuery(ssoInitiateQuerySchema), initiateSsoHandler);
        router.get('/sso/:provider/callback', ssoCallbackHandler);
        router.post('/sso/:provider/callback', express.urlencoded({ extended: false }), ssoCallbackHandler);
    }

    // JWKS — always mounted: every relying party and resource server needs
    // these to verify the access tokens this IdP issues.
    router.get('/.well-known/jwks.json', jwksHandler);
    router.get('/keys/:kid', authPublicKeyHandler);

    // Service mesh (S2S JWKS trust)
    if (features.serviceMesh) {
        router.post('/internal/service-keys', s2sBootstrapMiddleware, registerServiceKeyHandler);
        router.get('/.well-known/services-jwks.json', getServicesJwksHandler);
    }

    return router;
}

function resolveFeatures(input = {}) {
    if (input === null || typeof input !== 'object') throw new Error('buildRouter: opts.features must be an object');
    const unknown = Object.keys(input).filter((k) => !FEATURE_NAMES.includes(k));
    if (unknown.length > 0) {
        throw new Error(`buildRouter: unknown opts.features key(s): ${unknown.join(', ')} — expected any of ${FEATURE_NAMES.join(', ')}`);
    }
    return Object.fromEntries(FEATURE_NAMES.map((name) => [name, input[name] !== false]));
}

/** null when client management isn't requested; otherwise the validated, non-empty middleware list. Misconfiguration throws at startup rather than mounting the routes open. */
function resolveClientManagement(input) {
    if (input === undefined || input === null || input === false) return null;
    const list = typeof input.middleware === 'function' ? [input.middleware] : input.middleware;
    if (!Array.isArray(list) || list.length === 0) {
        throw new Error(
            'buildRouter: opts.clientManagement requires at least one middleware (your admin authentication/authorization) ' +
            'in opts.clientManagement.middleware — the OAuth2 client routes are never mounted unauthenticated.'
        );
    }
    if (!list.every((fn) => typeof fn === 'function')) {
        throw new Error('buildRouter: every entry in opts.clientManagement.middleware must be a middleware function');
    }
    return list;
}

export { serviceContextMiddleware }; // re-exported for building your own protected internal routes alongside this router
