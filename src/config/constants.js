// Generic constants inlined from the Okeav extraction audit (Phase 1 §3 / Phase 2 §4).
// None of these encode Okeav business taxonomy (accountType, role, capabilities) —
// those remain fully opaque to this package and live only inside `claims`.

export const IDENTITY_STATUS = Object.freeze({
    ACTIVE: 'ACTIVE',
    DISABLED: 'DISABLED',
    INVITED: 'INVITED',
    LOCKED: 'LOCKED',
    PENDING_VERIFICATION: 'PENDING_VERIFICATION',
    SUSPENDED: 'SUSPENDED',
    DELETED: 'DELETED',
});

export const KEY_STATUS = Object.freeze({
    ACTIVE: 'ACTIVE',
    ROTATING: 'ROTATING',
    RETIRED: 'RETIRED',
    REVOKED: 'REVOKED',
});

export const COOKIE_NAMES = Object.freeze({
    ACCESS_TOKEN: 'access_token',
    REFRESH_TOKEN: 'refresh_token',
});

export const CACHE_KEY_PREFIXES = Object.freeze({
    REFRESH_TOKEN: 'refresh-token',
    REVOKED_REFRESH_TOKEN: 'revoked-refresh-token',
    INTERNAL_AUTH_TOKEN: 'internal-auth-token',
    CLIENT_NONCE: 'client-nonce',
    SSO_STATE: 'sso-state',
    PUBLIC_KEY: 'public-key',
    WEBAUTHN_CHALLENGE: 'webauthn-challenge',
});

export const PASSWORD_POLICY_DEFAULTS = Object.freeze({
    minLength: 8,
    maxLength: 128,
    uppercase: /[A-Z]/,
    lowercase: /[a-z]/,
    number: /[0-9]/,
    special: /[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/,
});

export const NAME_REGEX = /^[\p{L}\s'-]*$/u;
export const MAX_EMAIL_LENGTH = 255;
export const MAX_NAME_LENGTH = 50;

export const TOKEN_TYPES = Object.freeze({
    ACCESS: 'access_token',
    MFA_CHALLENGE: 'mfa_challenge',
});

export const GRANT_TYPES = Object.freeze({
    AUTHORIZATION_CODE: 'authorization_code',
    CLIENT_CREDENTIALS: 'client_credentials',
    REFRESH_TOKEN: 'refresh_token',
});

export const CLIENT_TYPES = Object.freeze({
    CONFIDENTIAL: 'confidential',
    PUBLIC: 'public',
});

export const OAUTH_CLIENT_STATUS = Object.freeze({
    ACTIVE: 'ACTIVE',
    INACTIVE: 'INACTIVE',
    SUSPENDED: 'SUSPENDED',
    PENDING_APPROVAL: 'PENDING_APPROVAL',
});

export const DEFAULT_TTL_SECONDS = Object.freeze({
    accessToken: 60 * 60,
    idToken: 60 * 60,
    refreshToken: 30 * 24 * 60 * 60,
    internalToken: 30,
    authCode: 10 * 60,
    revocationCache: 60 * 60,
    refreshTokenCache: 60 * 60,
    passwordReset: 15 * 60,
    emailVerification: 24 * 60 * 60,
    magicLink: 15 * 60,
    mfaChallenge: 5 * 60,
    ssoState: 10 * 60,
    ssoExchange: 2 * 60,
    discoveryCache: 60 * 60,
    webauthnChallenge: 5 * 60,
});

// Request-rate limiting — a distinct concern from `security.maxFailedLoginAttempts`
// (which locks an individual account after N wrong passwords, tracked forever
// on the user record). These limits throttle the *rate* of requests to an
// endpoint within a rolling window, tracked in the rate limiter's storage,
// and apply regardless of whether any individual request "succeeds."
export const DEFAULT_RATE_LIMITS = Object.freeze({
    loginPerIp: { max: 10, windowSeconds: 15 * 60 },
    loginPerEmail: { max: 5, windowSeconds: 15 * 60 },
    passwordResetPerIp: { max: 3, windowSeconds: 60 * 60 },
    mfaChallengePerIp: { max: 5, windowSeconds: 15 * 60 },
    refreshTokenPerIp: { max: 30, windowSeconds: 60 },
    magicLinkPerIp: { max: 3, windowSeconds: 60 * 60 },
});

// Outbound webhooks — additive to the in-process hooks, never a replacement.
// Delivery is fire-and-forget from the caller's perspective: nothing here is
// ever awaited by the request that triggered the event.
export const DEFAULT_WEBHOOK_CONFIG = Object.freeze({
    endpoints: [],
    maxAttempts: 5,
    retryBaseDelayMs: 500,
    timeoutMs: 5000,
});
