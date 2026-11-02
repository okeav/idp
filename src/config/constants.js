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
    OAUTH_CONSENT: 'oauth-consent',
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

/** See classifyAccessToken in signing/token.service.js. */
export const ACCESS_TOKEN_KINDS = Object.freeze({
    FIRST_PARTY: 'first-party',
    OAUTH2_USER: 'oauth2-user',
    OAUTH2_CLIENT: 'oauth2-client',
});

/** What a session (refresh-token) row belongs to — a first-party login, or an OAuth2 client's grant. */
export const SESSION_KINDS = Object.freeze({
    FIRST_PARTY: 'first_party',
    OAUTH2: 'oauth2',
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
    passwordResetPerEmail: { max: 3, windowSeconds: 60 * 60 },
    mfaChallengePerIp: { max: 5, windowSeconds: 15 * 60 },
    refreshTokenPerIp: { max: 30, windowSeconds: 60 },
    magicLinkPerIp: { max: 3, windowSeconds: 60 * 60 },
    magicLinkPerEmail: { max: 3, windowSeconds: 60 * 60 },
    registerPerIp: { max: 10, windowSeconds: 60 * 60 },
    emailVerificationPerIp: { max: 20, windowSeconds: 15 * 60 },
    // Every request that makes this IdP send a verification email to an address
    // (registering it, re-registering a pending one, asking for a resend).
    verificationEmailPerEmail: { max: 3, windowSeconds: 60 * 60 },
    // Unauthenticated passkey login: options + verify both count (a login is 2 requests). Also
    // bounds how many challenges one IP can park in the cache.
    webauthnAuthenticationPerIp: { max: 60, windowSeconds: 5 * 60 },
    // /oauth2/token, /token/revoke, /token/introspect — client authentication is attempted on each.
    oauth2TokenPerIp: { max: 120, windowSeconds: 60 },
    // GET /sso/:provider — each call parks a state entry in the cache for ssoState seconds.
    ssoInitiatePerIp: { max: 30, windowSeconds: 5 * 60 },
    // POST /internal/service-keys — guesses at the bootstrap secret.
    serviceKeyRegistrationPerIp: { max: 20, windowSeconds: 15 * 60 },
});

// Per-ACCOUNT limit on wrong email-verification codes/tokens. When it is used
// up, every outstanding verification code for the account is deleted, so a
// 6-digit code can be guessed at most `maxFailedAttempts` times before the
// owner has to request a new one (which goes to their inbox, not the attacker's).
/**
 * Wrong 6-digit email-verification codes: `maxFailedAttempts` per verification ticket, and as many
 * again for attempts without one (per address). Window and lock are never shorter than the code's
 * lifetime (ttls.emailVerification — enforced where they are used), so a code gets a fixed number of
 * guesses for as long as it lives.
 */
export const DEFAULT_VERIFICATION_CODE_LOCKOUT = Object.freeze({
    maxFailedAttempts: 5,
    windowSeconds: 24 * 60 * 60,
    lockSeconds: 24 * 60 * 60,
});

// Per-ACCOUNT limit on wrong current passwords at /password/change. That endpoint is reached with a
// session, not a password, so without a limit anyone holding a stolen access token could guess the
// password there at bcrypt speed — no lockout, nothing to lose — and keep it after the token expires.
export const DEFAULT_PASSWORD_CHANGE_LOCKOUT = Object.freeze({
    maxFailedAttempts: 5,
    windowSeconds: 60 * 60,
    lockSeconds: 60 * 60,
});

// Per-ACCOUNT limit on failed second-factor attempts (TOTP, recovery codes,
// WebAuthn-as-MFA, and the codes that confirm/disable MFA), counted in
// storage so it holds across instances. Distinct from the per-IP
// `mfaChallengePerIp` rate limit above, which an attacker with many IPs
// sidesteps. Independent of `rateLimiting.enabled`.
export const DEFAULT_MFA_LOCKOUT = Object.freeze({
    maxFailedAttempts: 5,
    windowSeconds: 15 * 60,
    lockSeconds: 15 * 60,
});

// Outbound webhooks — additive to the in-process hooks, never a replacement.
// Delivery is fire-and-forget from the caller's perspective: nothing here is
// ever awaited by the request that triggered the event.
export const DEFAULT_WEBHOOK_CONFIG = Object.freeze({
    endpoints: [],
    maxAttempts: 5,
    retryBaseDelayMs: 500,
    timeoutMs: 5000,
    // Deliveries (with their retries) running at once; beyond this, events are dropped with a warning.
    maxInFlight: 100,
});
