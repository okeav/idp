import { DEFAULT_TTL_SECONDS, DEFAULT_RATE_LIMITS, DEFAULT_WEBHOOK_CONFIG } from './constants.js';

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
        ttls: { ...DEFAULT_TTL_SECONDS, ...config.ttls },
        security: {
            maxFailedLoginAttempts: 5,
            accountLockDurationMs: 30 * 60 * 1000,
            bcryptRounds: 12,
            emailHashPepper: config.security?.emailHashPepper,
            tokenHashSecret: config.security?.tokenHashSecret,
            ...config.security,
        },
        mfa: { issuerLabel: 'App', recoveryCodeCount: 10, ...config.mfa },
        magicLink: { allowSignupViaMagicLink: true, ...config.magicLink },
        // No defaults for rpID/rpName/origin — they're deployment-specific
        // (rpID in particular must be the *frontend's* registrable domain,
        // not necessarily this API's own host) and WebAuthn is opt-in, so
        // this is validated lazily at first handler call, not at startup.
        webauthn: config.webauthn || {},
        oauthProviders: config.oauthProviders || {},
        sso: config.sso || {},
        serviceMesh: { tokenMode: 'both', ...config.serviceMesh },
        rateLimiting: {
            enabled: true,
            adapter: 'memory',
            keyPrefix: 'ratelimit:',
            ...config.rateLimiting,
            login: { ...DEFAULT_RATE_LIMITS.loginPerIp, ...config.rateLimiting?.login },
            loginByEmail: { ...DEFAULT_RATE_LIMITS.loginPerEmail, ...config.rateLimiting?.loginByEmail },
            passwordReset: { ...DEFAULT_RATE_LIMITS.passwordResetPerIp, ...config.rateLimiting?.passwordReset },
            mfaChallenge: { ...DEFAULT_RATE_LIMITS.mfaChallengePerIp, ...config.rateLimiting?.mfaChallenge },
            refreshToken: { ...DEFAULT_RATE_LIMITS.refreshTokenPerIp, ...config.rateLimiting?.refreshToken },
            magicLink: { ...DEFAULT_RATE_LIMITS.magicLinkPerIp, ...config.rateLimiting?.magicLink },
        },
        hooks: config.hooks || {},
        webhooks: { ...DEFAULT_WEBHOOK_CONFIG, ...config.webhooks },
        // No defaults applied — `storage.factory`, when present, is used
        // as-is in place of the built-in Mongo adapter (see config/init.js).
        storage: config.storage || {},
    };
}
