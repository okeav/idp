/**
 * Optional convenience — builds an IdpConfig object from `process.env`
 * variables matching `.env.example`. This package never reads `process.env`
 * on its own initiative; using this helper (or not) is entirely your
 * choice — hand `initIdentityProvider()` a plain object built any way you
 * like (including from Infisical, AWS Secrets Manager, etc.).
 *
 * @param {NodeJS.ProcessEnv} [env]
 */
const TRUE_VALUES = new Set(['true', '1', 'yes', 'on']);
const FALSE_VALUES = new Set(['false', '0', 'no', 'off']);

/**
 * Strict parsing: an unset or blank variable means "use the default"; anything else must be a
 * recognisable value or startup fails. Before 0.4.0 only the exact string "true" was true, so
 * `IDP_COOKIE_SECURE=1` (or a blank `IDP_COOKIE_SECURE=`) silently turned secure cookies OFF, and a
 * non-numeric `IDP_MAX_FAILED_LOGIN_ATTEMPTS` became NaN, disabling account lockout.
 */
function parseBool(env, name, fallback) {
    const raw = env[name];
    if (raw === undefined || raw.trim() === '') return fallback;
    const v = raw.trim().toLowerCase();
    if (TRUE_VALUES.has(v)) return true;
    if (FALSE_VALUES.has(v)) return false;
    throw new Error(`${name} must be true/false (or 1/0, yes/no, on/off) — got "${raw}"`);
}

function parseInteger(env, name, fallback, { min = 0 } = {}) {
    const raw = env[name];
    if (raw === undefined || raw.trim() === '') return fallback;
    const n = Number(raw.trim());
    if (!Number.isInteger(n) || n < min) throw new Error(`${name} must be an integer >= ${min} — got "${raw}"`);
    return n;
}

const list = (raw) => (raw || '').split(',').map((x) => x.trim()).filter(Boolean);

export function configFromEnv(env = process.env) {
    const bool = (name, fallback) => parseBool(env, name, fallback);
    const int = (name, fallback, opts) => parseInteger(env, name, fallback, opts);

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
            redis: { host: env.IDP_REDIS_HOST, port: int('IDP_REDIS_PORT', 6379, { min: 1 }), username: env.IDP_REDIS_USERNAME || undefined, password: env.IDP_REDIS_PASSWORD || undefined, tls: bool('IDP_REDIS_TLS', false) },
        },
        signingKeys,
        cookies: {
            secure: bool('IDP_COOKIE_SECURE', env.NODE_ENV !== 'development'),
            sameSite: env.IDP_COOKIE_SAME_SITE || 'lax',
            domain: env.IDP_COOKIE_DOMAIN || undefined,
            trustedOrigins: list(env.IDP_COOKIE_TRUSTED_ORIGINS),
            refreshTokenInBody: (env.IDP_COOKIE_REFRESH_TOKEN_IN_BODY ?? '').trim().toLowerCase() === 'auto' ? 'auto' : bool('IDP_COOKIE_REFRESH_TOKEN_IN_BODY', 'auto'),
        },
        security: {
            maxFailedLoginAttempts: int('IDP_MAX_FAILED_LOGIN_ATTEMPTS', 5, { min: 1 }),
            accountLockDurationMs: int('IDP_ACCOUNT_LOCK_DURATION_MS', 30 * 60 * 1000, { min: 1000 }),
            bcryptRounds: int('IDP_BCRYPT_ROUNDS', 12, { min: 10 }),
            emailHashPepper: env.IDP_EMAIL_HASH_PEPPER,
            tokenHashSecret: env.IDP_TOKEN_HASH_SECRET,
        },
        mfa: {
            issuerLabel: env.IDP_MFA_ISSUER_LABEL || 'App',
            recoveryCodeCount: int('IDP_MFA_RECOVERY_CODE_COUNT', 10, { min: 1 }),
            enabled: bool('IDP_MFA_ENABLED', true),
            encryptionKey: env.IDP_MFA_ENCRYPTION_KEY || undefined,
            previousEncryptionKeys: (env.IDP_MFA_PREVIOUS_ENCRYPTION_KEYS || '').split(',').map((k) => k.trim()).filter(Boolean),
            requireEncrypted: bool('IDP_MFA_REQUIRE_ENCRYPTED', undefined),
            allowPlaintext: bool('IDP_MFA_ALLOW_PLAINTEXT', false),
        },
        session: {
            verifyOnEachRequest: bool('IDP_SESSION_VERIFY_ON_EACH_REQUEST', true),
        },
        oauthProviders: {
            google: env.IDP_SSO_GOOGLE_CLIENT_ID ? { clientId: env.IDP_SSO_GOOGLE_CLIENT_ID, clientSecret: env.IDP_SSO_GOOGLE_CLIENT_SECRET } : undefined,
            microsoft: env.IDP_SSO_MICROSOFT_CLIENT_ID ? { clientId: env.IDP_SSO_MICROSOFT_CLIENT_ID, clientSecret: env.IDP_SSO_MICROSOFT_CLIENT_SECRET, tenant: env.IDP_SSO_MICROSOFT_TENANT || 'common', trustEmail: bool('IDP_SSO_MICROSOFT_TRUST_EMAIL', false) } : undefined,
            github: env.IDP_SSO_GITHUB_CLIENT_ID ? { clientId: env.IDP_SSO_GITHUB_CLIENT_ID, clientSecret: env.IDP_SSO_GITHUB_CLIENT_SECRET } : undefined,
            apple: env.IDP_SSO_APPLE_CLIENT_ID ? { clientId: env.IDP_SSO_APPLE_CLIENT_ID, teamId: env.IDP_SSO_APPLE_TEAM_ID, keyId: env.IDP_SSO_APPLE_KEY_ID, privateKeyPem: env.IDP_SSO_APPLE_PRIVATE_KEY_B64 ? Buffer.from(env.IDP_SSO_APPLE_PRIVATE_KEY_B64, 'base64').toString('utf8') : undefined } : undefined,
            linkedin: env.IDP_SSO_LINKEDIN_CLIENT_ID ? { clientId: env.IDP_SSO_LINKEDIN_CLIENT_ID, clientSecret: env.IDP_SSO_LINKEDIN_CLIENT_SECRET } : undefined,
        },
        sso: {
            baseCallbackUrl: env.IDP_SSO_BASE_CALLBACK_URL || undefined,
            allowedRedirectOrigins: list(env.IDP_SSO_ALLOWED_REDIRECT_ORIGINS),
        },
        serviceMesh: {
            bootstrapSecret: env.IDP_S2S_BOOTSTRAP_SECRET || undefined,
            // "billing=secret1,orders=secret2"
            bootstrapSecrets: env.IDP_S2S_BOOTSTRAP_SECRETS
                ? Object.fromEntries(list(env.IDP_S2S_BOOTSTRAP_SECRETS).map((pair) => {
                    const i = pair.indexOf('=');
                    if (i < 1) throw new Error('IDP_S2S_BOOTSTRAP_SECRETS must be name=secret pairs, comma-separated');
                    return [pair.slice(0, i), pair.slice(i + 1)];
                }))
                : undefined,
            tokenMode: env.IDP_S2S_TOKEN_MODE || 'token',
            ownServiceName: env.IDP_S2S_OWN_SERVICE_NAME || undefined,
        },
        rateLimiting: {
            enabled: bool('IDP_RATE_LIMIT_ENABLED', true),
            adapter: env.IDP_RATE_LIMIT_ADAPTER || 'memory',
        },
        magicLink: {
            allowSignupViaMagicLink: bool('IDP_MAGIC_LINK_ALLOW_SIGNUP', true),
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
