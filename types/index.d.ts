import type { Request, Response, NextFunction, RequestHandler, Router } from 'express';

// ── Config ─────────────────────────────────────────────────────────────────

export interface SigningKeyEntry {
    /** Raw PEM or base64-encoded PEM. Omit on a key you only want to verify with (e.g. a RETIRED key kept for old tokens). */
    privateKey?: string;
    publicKey: string;
    status: 'ACTIVE' | 'ROTATING' | 'RETIRED' | 'REVOKED';
}

export interface StorageContract {
    /** Adapter-specific raw handle (e.g. a Mongoose connection or a pg Pool) — optional, not present on every adapter. */
    connection?: unknown;
    close(): Promise<void>;
    userRepository: unknown;
    sessionRepository: unknown;
    authorizationCodeRepository: unknown;
    consentRepository: unknown;
    oauthClientRepository: unknown;
    verificationTokenRepository: unknown;
    serviceKeyRepository: unknown;
    credentialRepository: unknown;
    // Loosely typed for now — the full per-repository shapes are documented
    // as JSDoc in src/storage/interfaces.js; a future pass may promote them
    // to real TS interfaces here.
}

export interface IdpConfig {
    issuer: string;
    /** Required unless `storage.factory` is provided. */
    mongo?: ({ uri: string } | { connection: unknown }) & { skipTransactionCheck?: boolean };
    /**
     * Plug in a non-Mongo storage adapter (e.g. `@okeav/idp-core-postgres`)
     * without idp-core ever importing it — `factory` is called with the same
     * signature as the built-in Mongo adapter's `createMongoStorage`. Omit
     * entirely to use the built-in Mongo adapter via `config.mongo`.
     */
    storage?: {
        factory?: (
            resolvedConfig: IdpConfig,
            deps: { hashEmail: (email: string) => string; normalizeEmail: (email: string) => string }
        ) => Promise<StorageContract>;
    };
    cache?: {
        adapter?: 'memory' | 'redis';
        keyPrefix?: string;
        redis?: { host: string; port: number; password?: string; db?: number; keepAliveMs?: number };
    };
    signingKeys: { keys: Record<string, SigningKeyEntry> };
    cookies?: { secure?: boolean; sameSite?: 'lax' | 'strict' | 'none'; domain?: string };
    ttls?: Partial<{
        accessToken: number; idToken: number; refreshToken: number; internalToken: number;
        authCode: number; revocationCache: number; refreshTokenCache: number;
        passwordReset: number; emailVerification: number; magicLink: number; mfaChallenge: number;
        ssoState: number; ssoExchange: number; discoveryCache: number; webauthnChallenge: number;
    }>;
    security: {
        emailHashPepper: string;
        tokenHashSecret: string;
        maxFailedLoginAttempts?: number;
        accountLockDurationMs?: number;
        bcryptRounds?: number;
    };
    mfa?: { issuerLabel?: string; recoveryCodeCount?: number };
    magicLink?: { allowSignupViaMagicLink?: boolean };
    /**
     * Fully opt-in — omit entirely to leave WebAuthn/passkey routes disabled.
     * Validated lazily on first WebAuthn handler call, not at
     * `initIdentityProvider()` startup. `rpID` must be the *frontend's*
     * registrable domain, not necessarily this API's own host.
     */
    webauthn?: { rpID?: string; rpName?: string; origin?: string | string[] };
    oauthProviders?: {
        google?: { clientId: string; clientSecret: string };
        github?: { clientId: string; clientSecret: string };
        microsoft?: { clientId: string; clientSecret: string; tenant?: string };
        apple?: { clientId: string; teamId: string; keyId: string; privateKeyPem: string };
        linkedin?: { clientId: string; clientSecret: string };
    };
    sso?: {
        baseCallbackUrl?: string;
        allowedRedirectOrigins?: string[];
    };
    serviceMesh?: {
        bootstrapSecret?: string;
        tokenMode?: 'token' | 'secret' | 'both';
        ownServiceName?: string;
        sharedSecret?: string;
    };
    rateLimiting?: {
        /** Set false to disable entirely — e.g. you already rate-limit at a gateway/CDN layer. Default true. */
        enabled?: boolean;
        adapter?: 'memory' | 'redis';
        keyPrefix?: string;
        /** Only read if adapter === 'redis'; omit to reuse cache.adapter's Redis connection when that's also 'redis'. */
        redis?: { host: string; port: number; password?: string; db?: number };
        login?: RateLimitRule;
        loginByEmail?: RateLimitRule;
        passwordReset?: RateLimitRule;
        mfaChallenge?: RateLimitRule;
        refreshToken?: RateLimitRule;
        magicLink?: RateLimitRule;
    };
    /**
     * Outbound webhook delivery — additive to `hooks` (in-process callbacks),
     * never a replacement. Every `onAuditLog`/named hook event also gets
     * POSTed, signed, to each configured endpoint. Omit or leave `endpoints`
     * empty to disable entirely (the default) — delivery failures, including
     * after exhausting retries, are only ever logged and never affect the
     * underlying auth operation.
     */
    webhooks?: {
        endpoints?: Array<{ url: string; secret: string }>;
        maxAttempts?: number;
        retryBaseDelayMs?: number;
        timeoutMs?: number;
    };
    hooks?: AuthHooks;
    logger?: Logger;
}

export interface Logger {
    info(obj: unknown, msg?: string): void;
    warn(obj: unknown, msg?: string): void;
    error(obj: unknown, msg?: string): void;
    debug(obj: unknown, msg?: string): void;
}

// ── Hooks ──────────────────────────────────────────────────────────────────

export interface AuditLogEvent {
    action: string;
    [key: string]: unknown;
    timestamp: string;
}

export interface AuthHooks {
    onAuditLog?(event: AuditLogEvent): void | Promise<void>;
    onVerificationEmailRequested?(payload: { email: string; firstName?: string; lastName?: string; verificationToken: string; verificationCode: string }): void | Promise<void>;
    onPasswordResetRequested?(payload: { email: string; resetToken: string; firstName?: string; lastName?: string }): void | Promise<void>;
    onPasswordChanged?(payload: { userId: string; email: string; firstName: string; lastName: string; locale: string; when: string; deviceInfo: string; ipAddress: string }): void | Promise<void>;
    onSuspiciousActivityDetected?(payload: { userId: string; email: string; firstName: string; lastName: string; locale: string; when: string; failedAttempts: number; unlocksAt: string }): void | Promise<void>;
    onNewDeviceLogin?(payload: { userId: string; email: string; firstName: string; lastName: string; locale: string; when: string; deviceInfo: string; ipAddress: string }): void | Promise<void>;
    onMagicLinkRequested?(payload: { email: string; magicLinkToken: string; firstName?: string; lastName?: string; isNewUser: boolean }): void | Promise<void>;
    /**
     * Called synchronously during login (password/MFA/SSO) to resolve the
     * opaque `claims` bag embedded in the issued access token. Defaults to
     * `() => ({})` if not supplied — the package never validates or
     * interprets whatever you return here (role/scopes/capabilities/tenant
     * id/anything is entirely up to you).
     */
    resolveAuthContext?(user: IdentityUser, ctx: { isNewUser: boolean; isNewLink?: boolean; method?: string; provider?: string; extra?: Record<string, unknown> }): { claims: Record<string, unknown> } | Promise<{ claims: Record<string, unknown> }>;
}

// ── Domain shapes ────────────────────────────────────────────────────────

export interface IdentityUser {
    id: string;
    email: string;
    status: 'ACTIVE' | 'DISABLED' | 'INVITED' | 'LOCKED' | 'PENDING_VERIFICATION' | 'SUSPENDED' | 'DELETED';
    mfaEnabled: boolean;
    profile: { firstName?: string; lastName?: string; displayName?: string; avatarUrl?: string; locale?: string; zoneinfo?: string };
    metadata: Record<string, unknown>;
    lastLoginAt?: Date;
    createdAt: Date;
    updatedAt: Date;
}

export interface IssuedToken {
    token: string;
    expiresAt: Date;
    kid: string;
    jti: string;
}

export interface AccessTokenClaims {
    sub: string;
    email?: string;
    claims?: Record<string, unknown>;
    type: 'access_token';
    iss: string;
    aud: string;
    jti: string;
    iat: number;
    exp: number;
}

// Express augmentation — `req.auth` / `req.serviceCaller` after the
// respective middleware runs; `req.validatedQuery` after validateQuery().
declare module 'express-serve-static-core' {
    interface Request {
        auth?: { userId: string; email?: string; claims: Record<string, unknown>; tokenMeta: { issuedAt: number; expiresAt: number; jti: string } };
        serviceCaller?: { name: string; scopes?: string[]; region?: string; source: 'token' | 'legacy-secret' };
        validatedQuery?: Record<string, unknown>;
    }
}

// ── Bootstrap ────────────────────────────────────────────────────────────

export function initIdentityProvider(config: IdpConfig): Promise<{ config: IdpConfig; logger: Logger; storage: StorageContract; cache: CacheAdapter }>;
export function configFromEnv(env?: NodeJS.ProcessEnv): IdpConfig;

// ── Errors ───────────────────────────────────────────────────────────────

export class IdpError extends Error {
    code: string;
    httpStatus: number;
    cause?: unknown;
    constructor(opts: { code: string; httpStatus?: number; message?: string; cause?: unknown });
}
export function isIdpError(err: unknown): err is IdpError;
export const ERROR_CODES: Record<string, string>;

// ── Token issuance / verification ────────────────────────────────────────

export function issueAccessToken(input: { sub: string; email?: string; claims?: Record<string, unknown> }, opts?: { ttlSeconds?: number; audience?: string }): Promise<IssuedToken>;
export function verifyAccessToken(token: string, opts?: { issuer?: string }): Promise<AccessTokenClaims>;
export function issueIdToken(user: IdentityUser, audience: string, nonce?: string): Promise<IssuedToken>;
export function issueOAuth2AccessToken(subject: { id: string }, client: { clientId: string; accessTokenTTL?: number }, scopes: string[]): Promise<IssuedToken>;
export function issueMfaChallengeToken(subjectId: string): Promise<string>;
export function verifyMfaChallengeToken(token: string): { sub: string; type: 'mfa_challenge' };
export function verifyIssuedToken(token: string, opts?: { issuer?: string }): Record<string, unknown> | null;

// ── JWKS / discovery ─────────────────────────────────────────────────────

export const jwksHandler: RequestHandler;
export const authPublicKeyHandler: RequestHandler;
export const openidConfigurationHandler: RequestHandler;

// ── Service mesh (S2S JWKS trust) ────────────────────────────────────────

export const registerServiceKeyHandler: RequestHandler;
export const getServicesJwksHandler: RequestHandler;
export const s2sBootstrapMiddleware: RequestHandler;
export function initServiceIdentity(opts: { serviceName: string; privateKeyPem: string; region?: string; idpBaseUrl: string; bootstrapSecret: string }): Promise<{ kid: string }>;
export function mintServiceToken(targetService: string, opts?: { scopes?: string[] }): string;
export const issueServiceToken: typeof mintServiceToken;
export function getServiceIdentity(): { serviceName: string; kid: string; region: string };
export function verifyServiceTokenRemote(token: string, opts: { expectedAud: string; expectedIss?: string; idpBaseUrl?: string }): Promise<Record<string, unknown>>;

// ── Middleware ───────────────────────────────────────────────────────────

export function authContextMiddleware(opts?: { issuer?: string }): RequestHandler;
export function serviceContextMiddleware(opts?: { ownServiceName?: string }): RequestHandler;
export function requireServiceCallerMiddleware(...allowedCallers: string[]): RequestHandler;
export function validateBody(schema: { parse: (input: unknown) => unknown }): RequestHandler;
export function validateQuery(schema: { parse: (input: unknown) => unknown }): RequestHandler;
export const cookieParser: (...args: unknown[]) => RequestHandler;

// ── Password / email identity flows ─────────────────────────────────────

export const registerHandler: RequestHandler;
export const verifyEmailHandler: RequestHandler;
export const resendVerificationEmailHandler: RequestHandler;
export const loginHandler: RequestHandler;
export const refreshTokenHandler: RequestHandler;
export const logoutHandler: RequestHandler;
export const logoutAllHandler: RequestHandler;
export const forgotPasswordHandler: RequestHandler;
export const resetPasswordHandler: RequestHandler;
export const changePasswordHandler: RequestHandler;
export const getMeHandler: RequestHandler;
export const updateMeHandler: RequestHandler;
export const deleteMeHandler: RequestHandler;
export const listSessionsHandler: RequestHandler;
export const revokeSessionHandler: RequestHandler;
export const revokeAllSessionsHandler: RequestHandler;

// ── MFA ──────────────────────────────────────────────────────────────────

export const getMfaStatusHandler: RequestHandler;
export const setupMfaHandler: RequestHandler;
export const confirmMfaHandler: RequestHandler;
export const disableMfaHandler: RequestHandler;
export const regenerateRecoveryCodesHandler: RequestHandler;
export const verifyMfaChallengeHandler: RequestHandler;

// ── OAuth2 authorization server + OIDC ───────────────────────────────────

export const registerOAuthClientHandler: RequestHandler;
export const getOAuthClientHandler: RequestHandler;
export const listOAuthClientsHandler: RequestHandler;
export const updateOAuthClientHandler: RequestHandler;
export const rotateOAuthClientSecretHandler: RequestHandler;
export const deactivateOAuthClientHandler: RequestHandler;
export const approveOAuthClientHandler: RequestHandler;
export const authorizeHandler: RequestHandler;
export const confirmConsentHandler: RequestHandler;
export const denyConsentHandler: RequestHandler;
export const tokenHandler: RequestHandler;
export const revokeTokenHandler: RequestHandler;
export const introspectTokenHandler: RequestHandler;
export const getConsentHandler: RequestHandler;
export const listConsentsHandler: RequestHandler;
export const revokeConsentHandler: RequestHandler;
export const userinfoHandler: RequestHandler;
export const endSessionHandler: RequestHandler;

// ── SSO ──────────────────────────────────────────────────────────────────

export const initiateSsoHandler: RequestHandler;
export const ssoCallbackHandler: RequestHandler;

// ── Magic link (passwordless email login) ────────────────────────────────

export const requestMagicLinkHandler: RequestHandler;
export const verifyMagicLinkHandler: RequestHandler;

// ── WebAuthn / passkeys ──────────────────────────────────────────────────
// Registration always requires an authenticated caller (adding a passkey to
// an existing account). Primary authentication requires no prior auth
// (passwordless login). The MFA variants complete the challenge
// `loginHandler` issued when `user.mfaEnabled`, as an alternative to
// `verifyMfaChallengeHandler` (TOTP) — both draw on the same stored
// credentials, but are distinct ceremonies scoped differently (usernameless/
// discoverable for primary login vs. scoped to one known user for MFA).

export const generateRegistrationOptionsHandler: RequestHandler;
export const verifyRegistrationHandler: RequestHandler;
export const generateAuthenticationOptionsHandler: RequestHandler;
export const verifyAuthenticationHandler: RequestHandler;
export const generateMfaWebauthnChallengeOptionsHandler: RequestHandler;
export const verifyMfaWebauthnChallengeHandler: RequestHandler;

// ── Cache adapters ───────────────────────────────────────────────────────

export interface CacheAdapter {
    get(key: string): Promise<unknown | null>;
    set(key: string, value: unknown, ttlSeconds?: number): Promise<void>;
    del(key: string): Promise<void>;
    expire(key: string, ttlSeconds: number): Promise<void>;
}
export class MemoryCacheAdapter implements CacheAdapter {
    constructor(opts?: { sweepIntervalMs?: number });
    get(key: string): Promise<unknown | null>;
    set(key: string, value: unknown, ttlSeconds?: number): Promise<void>;
    del(key: string): Promise<void>;
    expire(key: string, ttlSeconds: number): Promise<void>;
    close(): void;
}
export class RedisCacheAdapter implements CacheAdapter {
    constructor(opts: { redis: unknown });
    get(key: string): Promise<unknown | null>;
    set(key: string, value: unknown, ttlSeconds?: number): Promise<void>;
    del(key: string): Promise<void>;
    expire(key: string, ttlSeconds: number): Promise<void>;
}
export function createRedisCacheAdapter(opts: { host: string; port: number; password?: string; db?: number; keepAliveMs?: number }): Promise<RedisCacheAdapter>;

// ── Rate limiter adapters ────────────────────────────────────────────────

export interface RateLimitRule {
    max?: number;
    windowSeconds?: number;
}
export interface RateLimitResult {
    allowed: boolean;
    remaining: number;
    resetAt: number;
}
export interface RateLimiter {
    check(key: string): Promise<RateLimitResult>;
    increment(key: string, opts: { max: number; windowSeconds: number }): Promise<RateLimitResult>;
    reset(key: string): Promise<void>;
}
export class MemoryRateLimiter implements RateLimiter {
    constructor(opts?: { sweepIntervalMs?: number });
    check(key: string): Promise<RateLimitResult>;
    increment(key: string, opts: { max: number; windowSeconds: number }): Promise<RateLimitResult>;
    reset(key: string): Promise<void>;
    close(): void;
}
export class RedisRateLimiter implements RateLimiter {
    constructor(opts: { redis: unknown });
    check(key: string): Promise<RateLimitResult>;
    increment(key: string, opts: { max: number; windowSeconds: number }): Promise<RateLimitResult>;
    reset(key: string): Promise<void>;
}
export function createRedisRateLimiter(opts: { redis?: unknown; host?: string; port?: number; password?: string; db?: number }): Promise<RedisRateLimiter>;

// ── Outbound webhooks ────────────────────────────────────────────────────

export class WebhookDispatcher {
    constructor(opts: { endpoints?: Array<{ url: string; secret: string }>; maxAttempts?: number; retryBaseDelayMs?: number; timeoutMs?: number }, logger?: Logger);
    readonly isNoop: boolean;
    /** Fire-and-forget — never returns a promise callers need (or are expected) to await. */
    dispatch(event: string, payload: unknown): void;
}
/**
 * For consumers receiving webhook deliveries from this package. Verifies the
 * `X-Idp-Signature` header (`t=<unix seconds>,v1=<hex hmac>`) against the
 * exact raw (unparsed) request body.
 */
export function verifyWebhookSignature(secret: string, rawBody: string, signatureHeader: string | undefined, opts?: { toleranceSeconds?: number }): boolean;

// ── Schemas ──────────────────────────────────────────────────────────────

export const schemas: Record<string, { parse: (input: unknown) => unknown }>;

// ── Router convenience ───────────────────────────────────────────────────

export function buildRouter(opts?: { ownServiceName?: string }): Router;
