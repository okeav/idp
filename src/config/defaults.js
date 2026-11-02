import { DEFAULT_TTL_SECONDS, DEFAULT_RATE_LIMITS, DEFAULT_WEBHOOK_CONFIG, DEFAULT_MFA_LOCKOUT, DEFAULT_VERIFICATION_CODE_LOCKOUT } from './constants.js';

export function withDefaults(config = {}) {
    if (!config.issuer) throw new Error('config.issuer is required');
    if (!config.mongo && !config.storage?.factory) {
        throw new Error('config.mongo (uri or connection) is required unless config.storage.factory is provided');
    }
    if (!config.signingKeys?.keys || Object.keys(config.signingKeys.keys).length === 0) {
        throw new Error('config.signingKeys.keys is required (at least one ACTIVE signing key)');
    }

    return {
        ...config,
        cache: { adapter: 'memory', keyPrefix: 'idp:', ...config.cache },
        cookies: { secure: process.env.NODE_ENV !== 'development', sameSite: 'lax', domain: undefined, ...config.cookies },
        // verifyOnEachRequest (default true since 0.3.0): authContextMiddleware
        // checks the token's session row in storage on every request, so a
        // logout-all / password reset takes effect on every instance at once.
        // recentAuthMaxAgeSeconds: how recent a login must be for requireRecentAuth (passkey / MFA
        // enrolment, account and passkey deletion).
        session: { reresolveClaimsOnRefresh: false, verifyOnEachRequest: true, recentAuthMaxAgeSeconds: 15 * 60,
            // A refresh-token family (one login) ends after this however actively it's refreshed.
            absoluteLifetimeSeconds: 90 * 24 * 60 * 60,
            // A rotated refresh token presented again within this window (two tabs refreshing at
            // once) is just refused; after it, it revokes the whole family as a stolen-token signal.
            refreshReuseGraceSeconds: 10,
            ...config.session },
        ttls: { ...DEFAULT_TTL_SECONDS, ...config.ttls },
        security: {
            maxFailedLoginAttempts: 5,
            accountLockDurationMs: 30 * 60 * 1000,
            bcryptRounds: 12,
            emailHashPepper: config.security?.emailHashPepper,
            tokenHashSecret: config.security?.tokenHashSecret,
            ...config.security,
            verificationCodeLockout: { ...DEFAULT_VERIFICATION_CODE_LOCKOUT, ...config.security?.verificationCodeLockout },
        },
        mfa: {
            issuerLabel: 'App',
            recoveryCodeCount: 10,
            // TOTP MFA is on by default, which (since 0.3.0) means a key —
            // encryptionKey or secretCipher — is required at startup. See mfa/secrets.js.
            enabled: true,
            allowPlaintext: false,
            requireEncrypted: false,
            previousEncryptionKeys: [],
            ...config.mfa,
            lockout: { ...DEFAULT_MFA_LOCKOUT, ...config.mfa?.lockout },
        },
        magicLink: { allowSignupViaMagicLink: true, ...config.magicLink },
        // No defaults for rpID/rpName/origin — they're deployment-specific
        // (rpID in particular must be the *frontend's* registrable domain,
        // not necessarily this API's own host) and WebAuthn is opt-in, so
        // this is validated lazily at first handler call, not at startup.
        webauthn: config.webauthn || {},
        oauthProviders: config.oauthProviders || {},
        sso: config.sso || {},
        // requirePkce: 'all' (default) or 'public' — see oauth2/authorize.controller.js.
        oauth2: { requirePkce: 'all', ...config.oauth2 },
        serviceMesh: { tokenMode: 'both', ...config.serviceMesh },
        rateLimiting: {
            enabled: true,
            adapter: 'memory',
            keyPrefix: 'ratelimit:',
            ...config.rateLimiting,
            login: { ...DEFAULT_RATE_LIMITS.loginPerIp, ...config.rateLimiting?.login },
            loginByEmail: { ...DEFAULT_RATE_LIMITS.loginPerEmail, ...config.rateLimiting?.loginByEmail },
            passwordReset: { ...DEFAULT_RATE_LIMITS.passwordResetPerIp, ...config.rateLimiting?.passwordReset },
            passwordResetByEmail: { ...DEFAULT_RATE_LIMITS.passwordResetPerEmail, ...config.rateLimiting?.passwordResetByEmail },
            mfaChallenge: { ...DEFAULT_RATE_LIMITS.mfaChallengePerIp, ...config.rateLimiting?.mfaChallenge },
            refreshToken: { ...DEFAULT_RATE_LIMITS.refreshTokenPerIp, ...config.rateLimiting?.refreshToken },
            magicLink: { ...DEFAULT_RATE_LIMITS.magicLinkPerIp, ...config.rateLimiting?.magicLink },
            register: { ...DEFAULT_RATE_LIMITS.registerPerIp, ...config.rateLimiting?.register },
            emailVerification: { ...DEFAULT_RATE_LIMITS.emailVerificationPerIp, ...config.rateLimiting?.emailVerification },
            verificationEmailByEmail: { ...DEFAULT_RATE_LIMITS.verificationEmailPerEmail, ...config.rateLimiting?.verificationEmailByEmail },
            webauthnAuthentication: { ...DEFAULT_RATE_LIMITS.webauthnAuthenticationPerIp, ...config.rateLimiting?.webauthnAuthentication },
            oauth2Token: { ...DEFAULT_RATE_LIMITS.oauth2TokenPerIp, ...config.rateLimiting?.oauth2Token },
        },
        hooks: config.hooks || {},
        webhooks: { ...DEFAULT_WEBHOOK_CONFIG, ...config.webhooks },
        // No defaults applied — `storage.factory`, when present, is used
        // as-is in place of the built-in Mongo adapter (see config/init.js).
        storage: config.storage || {},
    };
}
