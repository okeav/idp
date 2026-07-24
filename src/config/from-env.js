/**
 * Optional convenience — builds an IdpConfig object from `process.env`
 * variables matching `.env.example`. This package never reads `process.env`
 * on its own initiative; using this helper (or not) is entirely your
 * choice — hand `initIdentityProvider()` a plain object built any way you
 * like (including from Infisical, AWS Secrets Manager, etc.).
 *
 * @param {NodeJS.ProcessEnv} [env]
 */
export function configFromEnv(env = process.env) {
    const bool = (v, fallback) => (v === undefined ? fallback : v === 'true');
    const num = (v, fallback) => (v === undefined || v === '' ? fallback : Number(v));

    const signingKeys = { keys: {} };
    if (env.IDP_SIGNING_KEY_CURRENT_KID) {
        signingKeys.keys[env.IDP_SIGNING_KEY_CURRENT_KID] = {
            privateKey: env.IDP_SIGNING_KEY_CURRENT_PRIVATE_B64,
            publicKey: env.IDP_SIGNING_KEY_CURRENT_PUBLIC_B64,
            status: 'ACTIVE',
        };
    }
    if (env.IDP_SIGNING_KEY_PREVIOUS_KID) {
        signingKeys.keys[env.IDP_SIGNING_KEY_PREVIOUS_KID] = {
            privateKey: env.IDP_SIGNING_KEY_PREVIOUS_PRIVATE_B64,
            publicKey: env.IDP_SIGNING_KEY_PREVIOUS_PUBLIC_B64,
            status: 'ROTATING',
        };
    }

    return {
        issuer: env.IDP_ISSUER,
        mongo: { uri: env.IDP_MONGO_URI },
        cache: {
            adapter: env.IDP_CACHE_ADAPTER || 'memory',
            keyPrefix: env.IDP_CACHE_KEY_PREFIX || 'idp:',
            redis: { host: env.IDP_REDIS_HOST, port: num(env.IDP_REDIS_PORT, 6379), password: env.IDP_REDIS_PASSWORD || undefined },
        },
        signingKeys,
        cookies: {
            secure: bool(env.IDP_COOKIE_SECURE, env.NODE_ENV !== 'development'),
            sameSite: env.IDP_COOKIE_SAME_SITE || 'lax',
            domain: env.IDP_COOKIE_DOMAIN || undefined,
        },
        security: {
            maxFailedLoginAttempts: num(env.IDP_MAX_FAILED_LOGIN_ATTEMPTS, 5),
            accountLockDurationMs: num(env.IDP_ACCOUNT_LOCK_DURATION_MS, 30 * 60 * 1000),
            bcryptRounds: num(env.IDP_BCRYPT_ROUNDS, 12),
            emailHashPepper: env.IDP_EMAIL_HASH_PEPPER,
            tokenHashSecret: env.IDP_TOKEN_HASH_SECRET,
        },
        mfa: {
            issuerLabel: env.IDP_MFA_ISSUER_LABEL || 'App',
            recoveryCodeCount: num(env.IDP_MFA_RECOVERY_CODE_COUNT, 10),
        },
        oauthProviders: {
            google: env.IDP_SSO_GOOGLE_CLIENT_ID ? { clientId: env.IDP_SSO_GOOGLE_CLIENT_ID, clientSecret: env.IDP_SSO_GOOGLE_CLIENT_SECRET } : undefined,
            microsoft: env.IDP_SSO_MICROSOFT_CLIENT_ID ? { clientId: env.IDP_SSO_MICROSOFT_CLIENT_ID, clientSecret: env.IDP_SSO_MICROSOFT_CLIENT_SECRET, tenant: env.IDP_SSO_MICROSOFT_TENANT || 'common' } : undefined,
            github: env.IDP_SSO_GITHUB_CLIENT_ID ? { clientId: env.IDP_SSO_GITHUB_CLIENT_ID, clientSecret: env.IDP_SSO_GITHUB_CLIENT_SECRET } : undefined,
            apple: env.IDP_SSO_APPLE_CLIENT_ID ? { clientId: env.IDP_SSO_APPLE_CLIENT_ID, teamId: env.IDP_SSO_APPLE_TEAM_ID, keyId: env.IDP_SSO_APPLE_KEY_ID, privateKeyPem: env.IDP_SSO_APPLE_PRIVATE_KEY_B64 } : undefined,
            linkedin: env.IDP_SSO_LINKEDIN_CLIENT_ID ? { clientId: env.IDP_SSO_LINKEDIN_CLIENT_ID, clientSecret: env.IDP_SSO_LINKEDIN_CLIENT_SECRET } : undefined,
        },
        serviceMesh: {
            bootstrapSecret: env.IDP_S2S_BOOTSTRAP_SECRET,
            tokenMode: env.IDP_S2S_TOKEN_MODE || 'both',
        },
        rateLimiting: {
            enabled: bool(env.IDP_RATE_LIMIT_ENABLED, true),
            adapter: env.IDP_RATE_LIMIT_ADAPTER || 'memory',
        },
        magicLink: {
            allowSignupViaMagicLink: bool(env.IDP_MAGIC_LINK_ALLOW_SIGNUP, true),
        },
        // Only wired if IDP_WEBAUTHN_RP_ID is set — WebAuthn is fully opt-in
        // and deployment-specific (rpID must be the frontend's registrable
        // domain), so there's no sensible default to fall back to.
        webauthn: env.IDP_WEBAUTHN_RP_ID
            ? { rpID: env.IDP_WEBAUTHN_RP_ID, rpName: env.IDP_WEBAUTHN_RP_NAME || 'App', origin: env.IDP_WEBAUTHN_ORIGIN }
            : {},
        // Only supports a single endpoint via env vars (the common case) —
        // configure config.webhooks.endpoints directly for multiple.
        webhooks: env.IDP_WEBHOOK_URL
            ? { endpoints: [{ url: env.IDP_WEBHOOK_URL, secret: env.IDP_WEBHOOK_SECRET }] }
            : {},
    };
}
