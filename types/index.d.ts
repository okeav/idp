import type { Request, Response, NextFunction, RequestHandler, ErrorRequestHandler, Router } from 'express';

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
    /** Optional — see `AttemptCounterRepository`. Without it the attempt budgets (MFA and password-login lockouts, verification-code and password-change limits) are counted in-process only. */
    attemptCounterRepository?: AttemptCounterRepository;
    // Loosely typed for now — the full per-repository shapes are documented
    // as JSDoc in src/storage/interfaces.js; a future pass may promote them
    // to real TS interfaces here. 0.4.0 adds REQUIRED methods a custom adapter
    // must implement: userRepository.updateByIdIfStatus / bumpSessionEpoch,
    // sessionRepository.isFamilyRevoked / isFamilyLive / rotatedWithin / raiseFamilyEpoch,
    // verificationTokenRepository.findActive / clearCodes / replaceForUser — see
    // docs/api/repository-adapters.md. initIdentityProvider refuses an adapter missing any
    // required method (the list: REQUIRED_STORAGE_METHODS in src/storage/interfaces.js).
}

/**
 * Optional storage repository behind the attempt budgets (`mfa:<userId>`,
 * `password-login:<userId>`, `email-verification:<email hash>`,
 * `password-change:<userId>`, spent MFA challenges): atomic fixed-window
 * failure counters with a lock, shared by every app instance.
 * See src/storage/interfaces.js for the exact semantics `recordFailure` must have.
 */
export interface AttemptCounterRepository {
    get(key: string): Promise<{ count: number; windowExpiresAt: Date; lockedUntil: Date | null } | null>;
    recordFailure(key: string, opts: { max: number; windowSeconds: number; lockSeconds: number }): Promise<{ count: number; windowExpiresAt: Date; lockedUntil: Date | null }>;
    reset(key: string): Promise<void>;
    pruneExpired?(): Promise<{ deletedCount: number }>;
}

/**
 * At-rest encryption for TOTP secrets — plug in a KMS/HSM via
 * `config.mfa.secretCipher`. `encrypt`'s output is stored verbatim and must
 * not be a bare base32 string (that shape marks a legacy plain-text secret);
 * a prefix such as `kms:` is enough. `context` is the owning user's id —
 * bind it to the ciphertext so a value copied onto another user fails.
 */
export interface SecretCipher {
    encrypt(plaintext: string, opts: { context: string }): string | Promise<string>;
    decrypt(ciphertext: string, opts: { context: string }): string | Promise<string>;
    /** True when `ciphertext` was written under a non-current key; it is then re-encrypted on the next successful verify. */
    needsRotation?(ciphertext: string): boolean;
}

/** A 32-byte key, base64. A bare string's id is a fingerprint of the key; `{ id, key }` names it explicitly. */
export type MfaEncryptionKey = string | { id: string; key: string };

export interface IdpConfig {
    /** https URL (plain http only for localhost / 127.0.0.1 / [::1], or with NODE_ENV=development) — checked at startup. */
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
        redis?: { host: string; port: number; username?: string; password?: string; db?: number; tls?: boolean | Record<string, unknown>; keepAliveMs?: number };
    };
    signingKeys: { keys: Record<string, SigningKeyEntry> };
    cookies?: {
        /**
         * Default: NODE_ENV !== 'development'. Secure session cookies are named `__Host-access_token` /
         * `__Host-refresh_token` (or `__Secure-…` with `domain`); without Secure, plain `access_token` /
         * `refresh_token`.
         */
        secure?: boolean;
        /** Default 'lax' (case-insensitive). 'none' requires secure cookies (checked at startup). */
        sameSite?: 'lax' | 'strict' | 'none';
        /**
         * Share the session cookies with subdomains. Rules out the `__Host-` prefix: the cookies become
         * `__Secure-…`, and a request carrying one twice is refused (400 COOKIE_CONFLICT).
         */
        domain?: string;
        /**
         * Exact origins (e.g. `https://app.example.com` — no path, no trailing slash; checked at startup)
         * of your frontends that make cookie-authenticated requests. A cookie-authenticated
         * POST/PUT/PATCH/DELETE from any other origin is refused (403 CSRF_ORIGIN_REJECTED), as is any
         * browser request to an endpoint that sets or clears session cookies. The issuer's origin is
         * always trusted; Bearer-authenticated requests are unaffected.
         */
        trustedOrigins?: string[];
        /**
         * Whether login/refresh JSON bodies also carry the refresh token. Default `'auto'`: only for
         * non-browser clients — a browser request (it sends `Origin` or `Sec-Fetch-Site`) gets it in its
         * httpOnly cookie only. `true`: always (a browser app that keeps the token itself). `false`: never.
         */
        refreshTokenInBody?: boolean | 'auto';
        /**
         * The path the refresh-token cookie is scoped to. Default: `<router mount path>/session`, taken from
         * the request. Set it (e.g. `/auth/session`) to pin it when the mount path can vary in spelling.
         */
        sessionPath?: string;
    };
    registration?: {
        /** Persist the user-supplied `metadata` from POST /register. Default false — it is attacker-controlled. */
        acceptMetadata?: boolean;
    };
    session?: {
        /**
         * Default true (since 0.4.0): `POST /refresh` re-invokes `hooks.resolveAuthContext`, so a
         * role/capability change (a demotion, a suspension in your app) takes effect at the next
         * access-token rotation. Set false to carry the login-time `claims` forward verbatim — they
         * then stay frozen for the whole session family (up to `absoluteLifetimeSeconds`).
         */
        reresolveClaimsOnRefresh?: boolean;
        /**
         * Default true (since 0.3.0): `authContextMiddleware` looks up the
         * access token's session row (by `jti`) on every request and refuses
         * the token if the row is missing, revoked or expired — so logout-all,
         * password reset/change and session revocation take effect on every
         * instance immediately. Costs one indexed storage read per
         * authenticated request. Set false to fall back to the per-process
         * revocation cache only: logout-all and password reset/change then
         * don't revoke access tokens at all until they expire, and a single
         * logout/revocation only takes effect on the instance that handled it.
         */
        verifyOnEachRequest?: boolean;
        /** How recent (seconds) a login must be for `requireRecentAuth` — passkey/MFA enrolment, passkey and account deletion. Default 900. */
        recentAuthMaxAgeSeconds?: number;
        /** A login's refresh-token family ends after this however actively it is refreshed. Default 90 days. */
        absoluteLifetimeSeconds?: number;
        /** A rotated refresh token replayed within this many seconds is only refused; later, it revokes its whole family. Default 10. */
        refreshReuseGraceSeconds?: number;
    };
    /** Seconds; each must be a positive integer (checked at startup). */
    ttls?: Partial<{
        accessToken: number; idToken: number; refreshToken: number; internalToken: number;
        authCode: number; revocationCache: number; refreshTokenCache: number;
        passwordReset: number; emailVerification: number; magicLink: number; mfaChallenge: number;
        ssoState: number; ssoExchange: number; discoveryCache: number; webauthnChallenge: number;
    }>;
    security: {
        /** Random, at least 32 characters (checked at startup). Never rotate — it keys the email lookup index. */
        emailHashPepper: string;
        /**
         * Random, at least 32 characters, different from `emailHashPepper` (checked at startup). Every stored
         * token/code/link/recovery-code hash and HMAC-stored client secret is keyed by a key derived from it
         * per purpose. To rotate it, move the old value to `previousTokenHashSecrets`.
         */
        tokenHashSecret: string;
        /**
         * Earlier `tokenHashSecret` values, newest first (each at least 32 characters). What was hashed under
         * them still verifies; new hashes always use `tokenHashSecret`. Drop one once everything hashed under
         * it has expired or been replaced (see docs/api/bootstrap-config.md). Default [].
         */
        previousTokenHashSecrets?: string[];
        /** Wrong passwords per `accountLockDurationMs` window before password login (only) is locked — active accounts with a password only. Default 5. */
        maxFailedLoginAttempts?: number;
        /** The counting window and the password-login lock's length, in ms. Default 1_800_000 (30 min). */
        accountLockDurationMs?: number;
        /** Integer 10-15 (default 12). */
        bcryptRounds?: number;
        /** Tests only: allow bcryptRounds down to 4. */
        allowWeakBcryptRounds?: boolean;
        /**
         * Per-address limit on wrong 6-digit email-verification codes (the link token has no budget). When
         * used up, the outstanding codes are cleared; the emailed links keep working. Defaults: 5 in 3600s,
         * locked 900s.
         */
        verificationCodeLockout?: { maxFailedAttempts?: number; windowSeconds?: number; lockSeconds?: number };
        /** Per-account limit on wrong current passwords at /password/change. Defaults: 5 in 3600s, locked 3600s. */
        passwordChangeLockout?: { maxFailedAttempts?: number; windowSeconds?: number; lockSeconds?: number };
    };
    mfa?: {
        issuerLabel?: string;
        recoveryCodeCount?: number;
        /** Default true. When true, startup requires `encryptionKey` or `secretCipher` (unless `allowPlaintext`). Set false if you don't use TOTP MFA. */
        enabled?: boolean;
        /** Current AES-256-GCM key for TOTP secrets at rest. */
        encryptionKey?: MfaEncryptionKey;
        /** Retired keys still accepted for decryption during a rotation. */
        previousEncryptionKeys?: MfaEncryptionKey[];
        /** Custom cipher (e.g. KMS) — takes precedence over `encryptionKey`. */
        secretCipher?: SecretCipher;
        /**
         * Refuse plain-text secrets (left over from ≤0.2.x, or written straight into the database).
         * Default: true whenever `encryptionKey` or `secretCipher` is set — run `migrateMfaSecrets()` to
         * encrypt old ones, or set false to keep reading them during a migration.
         */
        requireEncrypted?: boolean;
        /** Development only: allow MFA with no key, storing secrets in plain text (logs a loud warning). */
        allowPlaintext?: boolean;
        /** Per-account second-factor lockout. Defaults: 5 failures in 900s lock for 900s. */
        lockout?: { maxFailedAttempts?: number; windowSeconds?: number; lockSeconds?: number };
    };
    magicLink?: { allowSignupViaMagicLink?: boolean };
    /**
     * Fully opt-in — omit entirely to leave WebAuthn/passkey routes disabled.
     * Validated lazily on first WebAuthn handler call, not at
     * `initIdentityProvider()` startup. `rpID` must be the *frontend's*
     * registrable domain, not necessarily this API's own host.
     */
    webauthn?: {
        rpID?: string; rpName?: string; origin?: string | string[];
        /**
         * Default false: passkey-login options ignore `email` and always ask for a discoverable credential, because
         * listing an address's credential ids reveals whether it has an account. Set true only if you rely on
         * non-discoverable credentials (unknown addresses then get a stable decoy id).
         */
        allowCredentialsByEmail?: boolean;
    };
    oauthProviders?: {
        google?: { clientId: string; clientSecret: string };
        github?: { clientId: string; clientSecret: string };
        /**
         * `tenant` defaults to `'common'`. With a multi-tenant authority (`common`, `organizations`,
         * `consumers`) the account's email is NOT trusted — any tenant admin can set it — so a
         * Microsoft identity can't create or link an account by email. Pin `tenant` to your own
         * tenant, or set `trustEmail: true` only if you accept that risk.
         */
        microsoft?: { clientId: string; clientSecret: string; tenant?: string; trustEmail?: boolean };
        apple?: { clientId: string; teamId: string; keyId: string; privateKeyPem: string };
        linkedin?: { clientId: string; clientSecret: string };
    };
    oauth2?: {
        /**
         * Which clients must use PKCE (S256) at /oauth2/authorize. `'all'` (default) — every client, the
         * RFC 9700 recommendation (a confidential client without PKCE is open to code injection);
         * `'public'` — public clients only (always required for them).
         */
        requirePkce?: 'all' | 'public';
    };
    oidc?: {
        /**
         * The IdP page that asks "sign out?" for RP-initiated logout. When set, `GET /session/end` without
         * a matching `id_token_hint` redirects there with its query parameters; the page POSTs them back to
         * `/session/end`. https (http only for localhost), on the issuer's origin or a `cookies.trustedOrigins`
         * origin (checked at startup). Unset: that GET answers `{ action: 'logout_confirmation_required' }`.
         */
        endSessionConfirmationUrl?: string;
    };
    /**
     * Bounds on this server's clock vs the database's (token, code and lockout lifetimes use the local
     * clock). Measured at startup — which fails past `maxSkewSeconds` — and every `checkIntervalSeconds`.
     */
    clock?: {
        /** Default 30. */
        maxSkewSeconds?: number;
        /** Default 2: a warning is logged past it. */
        warnSkewSeconds?: number;
        /** Default 600 (minimum 10). */
        checkIntervalSeconds?: number;
    };
    /** Required (startup fails otherwise) as soon as any `oauthProviders` entry has a `clientId`. */
    sso?: {
        /** Absolute base URL providers redirect back to (`<base>/sso/<provider>/callback`). https (http only for localhost, or with NODE_ENV=development). */
        baseCallbackUrl?: string;
        /** Origins (scheme://host[:port]) SSO may send the browser back to. https, or http only for localhost. */
        allowedRedirectOrigins?: string[];
        /** Timeout for each call to a provider (token exchange, userinfo). Default 10000. */
        providerTimeoutMs?: number;
    };
    serviceMesh?: {
        /** One registration credential per service (preferred): `{ billing: '<secret>', ... }`. Proves which service registers, and lets it rotate its key. Each ≥ 32 characters and different from `bootstrapSecret`. */
        bootstrapSecrets?: Record<string, string>;
        /** Legacy shared registration secret (≥ 32 characters): can register a NEW name only (never one listed in bootstrapSecrets), never replace an existing service's key. */
        bootstrapSecret?: string;
        /** Names allowed to register at all. */
        allowedServiceNames?: string[];
        /** Default 'token'. 'secret'/'both' accept the shared secret with an unverified x-service-name. */
        tokenMode?: 'token' | 'secret' | 'both';
        ownServiceName?: string;
        /** ≥ 32 characters. */
        sharedSecret?: string;
        /** Let requireServiceCallerMiddleware accept shared-secret callers (their name is unverified). Default false. */
        allowLegacySecretCallers?: boolean;
        /** How long a rotated-away (ROTATING) service key still verifies, in seconds. Default 3600. */
        rotationGraceSeconds?: number;
    };
    rateLimiting?: {
        /** Set false to disable entirely — e.g. you already rate-limit at a gateway/CDN layer. Default true. */
        enabled?: boolean;
        adapter?: 'memory' | 'redis';
        keyPrefix?: string;
        /** Only read if adapter === 'redis'; omit to reuse cache.adapter's Redis connection when that's also 'redis'. */
        redis?: { host: string; port: number; username?: string; password?: string; db?: number; tls?: boolean | Record<string, unknown> };
        login?: RateLimitRule;
        loginByEmail?: RateLimitRule;
        passwordReset?: RateLimitRule;
        /** Password-reset requests per address. Default 3/hour. */
        passwordResetByEmail?: RateLimitRule;
        mfaChallenge?: RateLimitRule;
        refreshToken?: RateLimitRule;
        magicLink?: RateLimitRule;
        /** Magic-link requests per address. Default 3/hour. */
        magicLinkByEmail?: RateLimitRule;
        /** POST /register and /register/resend-verification, per IP. Default 10/hour. */
        register?: RateLimitRule;
        /** POST /register/verify-email, per IP. Default 20/15min. */
        emailVerification?: RateLimitRule;
        /** Verification emails sent to one address (register, re-register, resend). Default 3/hour. */
        verificationEmailByEmail?: RateLimitRule;
        /** POST /webauthn/authentication/options and /verify (unauthenticated passkey login), per IP. Default 60/5min. */
        webauthnAuthentication?: RateLimitRule;
        /** /oauth2/token, /oauth2/token/revoke and /oauth2/token/introspect, per IP. Default 120/min. */
        oauth2Token?: RateLimitRule;
        /** GET /sso/:provider, per IP. Default 30/5min. */
        ssoInitiate?: RateLimitRule;
        /** POST /internal/service-keys (bootstrap-secret guesses), per IP. Default 20/15min. */
        serviceKeyRegistration?: RateLimitRule;
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
        endpoints?: WebhookEndpoint[];
        maxAttempts?: number;
        retryBaseDelayMs?: number;
        timeoutMs?: number;
        /** Deliveries (with retries) in flight at once; beyond this, events are dropped with a warning. Default 100. */
        maxInFlight?: number;
    };
    hooks?: AuthHooks;
    /** How long a hook is awaited before the request carries on without it (it keeps running). Default 10000. */
    hookTimeoutMs?: number;
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
    /** Present (true) on tokens with no session row behind them — see `issueAccessToken`. */
    sessionless?: boolean;
    /** OAuth2-issued tokens only: the client the token was issued to (also its `aud`). */
    client_id?: string;
    /** OAuth2-issued tokens only: space-separated granted scopes. */
    scope?: string;
    /** `'client_credentials'` on machine tokens (no user; `sub` is the client id). */
    gty?: 'client_credentials';
}

/**
 * Which party an access token was issued to. `authContextMiddleware` / `verifyAccessToken`
 * accept only `'first-party'` unless told otherwise — a token this IdP issued to a third-party
 * OAuth2 client is never a credential for the IdP's own routes.
 */
export type AccessTokenKind = 'first-party' | 'oauth2-user' | 'oauth2-client';

export interface VerifyAccessTokenOptions {
    issuer?: string;
    /** The `aud` a first-party token must carry. Default: the issuer. */
    audience?: string | string[];
    /** Token kinds accepted. Default `['first-party']`. */
    accept?: AccessTokenKind[];
}

// Express augmentation — `req.auth` / `req.serviceCaller` after the
// respective middleware runs; `req.validatedQuery` after validateQuery().
declare module 'express-serve-static-core' {
    interface Request {
        auth?: {
            /** Undefined for `'oauth2-client'` (client_credentials) tokens — there is no user. */
            userId?: string;
            email?: string;
            claims: Record<string, unknown>;
            tokenKind: AccessTokenKind;
            /** OAuth2 tokens only. */
            clientId?: string;
            /** OAuth2 tokens only: the granted scopes. */
            scopes?: string[];
            /** `authTime`: when the user last actually logged in (seconds), carried across refreshes; null if unknown. */
            tokenMeta: { issuedAt: number; expiresAt: number; jti: string; authTime: number | null };
        };
        /** `scopes` are whatever the calling service put in its own token — not granted by anyone; never authorize on them alone. */
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
    /** Mirrors httpStatus, for Express's default handler and similar conventions. */
    status: number;
    statusCode: number;
    /** True below 500: the message is written for clients. */
    expose: boolean;
    cause?: unknown;
    constructor(opts: { code: string; httpStatus?: number; message?: string; cause?: unknown });
}
export function isIdpError(err: unknown): err is IdpError;
/**
 * Express error handler safe for the internet: IdpError < 500 → { error, message }; anything else → 500 { error } with no internals.
 * 5xx errors are logged (path only) through `opts.logger`, or by default the logger given to `initIdentityProvider`.
 */
export function idpErrorHandler(opts?: { logger?: Logger }): ErrorRequestHandler;
export const ERROR_CODES: Record<string, string>;

// ── Token issuance / verification ────────────────────────────────────────

/**
 * Tokens minted through this export have no session row, so by default they
 * carry `sessionless: true` and are exempt from `session.verifyOnEachRequest`.
 * Pass `sessionless: false` only if you created a session row with this
 * token's `jti` yourself.
 */
export function issueAccessToken(input: { sub: string; email?: string; claims?: Record<string, unknown> }, opts?: { ttlSeconds?: number; audience?: string; sessionless?: boolean; authTime?: number }): Promise<IssuedToken>;
/**
 * Verifies signature, issuer, expiry, type and audience/kind — NOT revocation. A resource server that
 * must refuse revoked sessions (logout-all, password reset) should use `authContextMiddleware`, which
 * also checks the session store (`session.verifyOnEachRequest`).
 */
export function verifyAccessToken(token: string, opts?: VerifyAccessTokenOptions): Promise<AccessTokenClaims>;
/** `opts.scopes` decide which user claims are released (default: openid email profile); `opts.authTime` (seconds) becomes `auth_time`. */
export function issueIdToken(user: IdentityUser, audience: string, nonce?: string, opts?: { scopes?: string[]; authTime?: number; ttlSeconds?: number }): Promise<IssuedToken>;
export function issueOAuth2AccessToken(subject: { id: string }, client: { clientId: string; accessTokenTTL?: number }, scopes: string[], opts?: { sessionless?: boolean }): Promise<IssuedToken>;
export function issueMfaChallengeToken(subjectId: string): Promise<string>;
/** For health checks: this server's clock minus the database's (`level`: 'unknown' when the storage adapter can't tell the time). */
export function checkClockSkew(): Promise<{ skewMs: number | null; ok: boolean; level: 'ok' | 'warn' | 'error' | 'unknown' }>;
/** Checks signature, expiry, `type`, `iss` (the issuer) and `aud` (`<issuer>#mfa-challenge`). */
export function verifyMfaChallengeToken(token: string): { sub: string; type: 'mfa_challenge'; iss: string; aud: string; jti: string; iat: number; exp: number };
export function verifyIssuedToken(token: string, opts?: { issuer?: string }): Record<string, unknown> | null;

// ── JWKS / discovery ─────────────────────────────────────────────────────

export const jwksHandler: RequestHandler;
export const authPublicKeyHandler: RequestHandler;
export const openidConfigurationHandler: RequestHandler;

// ── Service mesh (S2S JWKS trust) ────────────────────────────────────────

export const registerServiceKeyHandler: RequestHandler;
export const getServicesJwksHandler: RequestHandler;
/** Revokes a service key (no longer published or accepted). Resolves whether a key was found. */
export function revokeServiceKey(kid: string): Promise<boolean>;
export const s2sBootstrapMiddleware: RequestHandler;
/** `idpBaseUrl` must be https (http only for localhost, or with NODE_ENV=development) — throws otherwise. */
export function initServiceIdentity(opts: { serviceName: string; privateKeyPem: string; region?: string; idpBaseUrl: string; bootstrapSecret: string }): Promise<{ kid: string }>;
export function mintServiceToken(targetService: string, opts?: { scopes?: string[] }): string;
export const issueServiceToken: typeof mintServiceToken;
export function getServiceIdentity(): { serviceName: string; kid: string; region: string };
/** `idpBaseUrl` (or the one from `initServiceIdentity`) must be https (http only for localhost, or with NODE_ENV=development). */
export function verifyServiceTokenRemote(token: string, opts: { expectedAud: string; expectedIss?: string; idpBaseUrl?: string }): Promise<Record<string, unknown>>;

// ── Middleware ───────────────────────────────────────────────────────────

export function authContextMiddleware(opts?: VerifyAccessTokenOptions & { optional?: boolean }): RequestHandler;
/** Step-up gate: 401 REAUTHENTICATION_REQUIRED unless the user logged in within `maxAgeSeconds` (default `session.recentAuthMaxAgeSeconds`). Mount after authContextMiddleware. */
export function requireRecentAuth(opts?: { maxAgeSeconds?: number }): RequestHandler;
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
/** GET /me/passkeys and DELETE /me/passkeys/:credentialId (owner-scoped). */
export const listPasskeysHandler: RequestHandler;
export const deletePasskeyHandler: RequestHandler;
export const generateAuthenticationOptionsHandler: RequestHandler;
export const verifyAuthenticationHandler: RequestHandler;
export const generateMfaWebauthnChallengeOptionsHandler: RequestHandler;
export const verifyMfaWebauthnChallengeHandler: RequestHandler;

// ── MFA secret encryption ────────────────────────────────────────────────

/** Built-in AES-256-GCM cipher. Stored format: `v1:<keyId>:<iv>:<ciphertext>:<tag>` (base64url parts). */
export class AesGcmSecretCipher implements SecretCipher {
    constructor(opts: { currentKey: MfaEncryptionKey; previousKeys?: MfaEncryptionKey[] });
    readonly currentKeyId: string;
    encrypt(plaintext: string, opts?: { context?: string }): string;
    decrypt(ciphertext: string, opts?: { context?: string }): string;
    needsRotation(ciphertext: string): boolean;
}
/**
 * Encrypts every plain-text `mfaSecret`/`mfaTempSecret` (and re-encrypts any
 * under a non-current key) in one pass. Idempotent; safe while serving
 * traffic. Per-user errors are collected in `failed`, not thrown.
 */
export function migrateMfaSecrets(opts?: { batchSize?: number; dryRun?: boolean }): Promise<{ scanned: number; encrypted: number; reencrypted: number; failed: Array<{ userId: string; error: string }> }>;

// ── Cache adapters ───────────────────────────────────────────────────────

export interface CacheAdapter {
    get(key: string): Promise<unknown | null>;
    set(key: string, value: unknown, ttlSeconds?: number): Promise<void>;
    del(key: string): Promise<void>;
    expire(key: string, ttlSeconds: number): Promise<void>;
    /** Atomic get-and-delete — of two concurrent callers, exactly one gets the value. */
    take(key: string): Promise<unknown | null>;
}
export class MemoryCacheAdapter implements CacheAdapter {
    /** `maxEntries` (default 100000): when full, expired then oldest entries are evicted. */
    constructor(opts?: { sweepIntervalMs?: number; maxEntries?: number });
    get(key: string): Promise<unknown | null>;
    set(key: string, value: unknown, ttlSeconds?: number): Promise<void>;
    del(key: string): Promise<void>;
    expire(key: string, ttlSeconds: number): Promise<void>;
    /** Atomic get-and-delete — of two concurrent callers, exactly one gets the value. */
    take(key: string): Promise<unknown | null>;
    close(): void;
}
export class RedisCacheAdapter implements CacheAdapter {
    constructor(opts: { redis: unknown });
    get(key: string): Promise<unknown | null>;
    set(key: string, value: unknown, ttlSeconds?: number): Promise<void>;
    del(key: string): Promise<void>;
    expire(key: string, ttlSeconds: number): Promise<void>;
    /** Atomic get-and-delete — of two concurrent callers, exactly one gets the value. */
    take(key: string): Promise<unknown | null>;
}
export function createRedisCacheAdapter(opts: { host: string; port: number; username?: string; password?: string; db?: number; tls?: boolean | Record<string, unknown>; keepAliveMs?: number }): Promise<RedisCacheAdapter>;

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
    /**
     * `maxKeys` (default 500000): when full, expired windows and then the oldest counters that haven't
     * reached their limit are evicted; a NEW key is refused (an error — fail-closed call sites answer 503)
     * only if every counter is exhausted.
     */
    constructor(opts?: { sweepIntervalMs?: number; maxKeys?: number });
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
export function createRedisRateLimiter(opts: { redis?: unknown; host?: string; port?: number; username?: string; password?: string; db?: number; tls?: boolean | Record<string, unknown> }): Promise<RedisRateLimiter>;
/** Used when `rateLimiting.enabled === false` — every check passes. */
export class NoopRateLimiter implements RateLimiter {
    check(key: string): Promise<RateLimitResult>;
    increment(key: string, opts: { max: number; windowSeconds: number }): Promise<RateLimitResult>;
    reset(key: string): Promise<void>;
}

// ── Outbound webhooks ────────────────────────────────────────────────────

/**
 * `url` must be https (http only for localhost); `secret` at least 16 characters. `events` limits which
 * events the endpoint receives. Credential fields (reset/magic-link tokens, verification codes) are
 * stripped unless `includeCredentials` — set it only on the endpoint that sends those emails.
 */
export interface WebhookEndpoint {
    url: string;
    secret: string;
    events?: string[];
    includeCredentials?: boolean;
}
export class WebhookDispatcher {
    constructor(opts: { endpoints?: WebhookEndpoint[]; maxAttempts?: number; retryBaseDelayMs?: number; timeoutMs?: number; maxInFlight?: number }, logger?: Logger);
    readonly isNoop: boolean;
    /** Fire-and-forget — never returns a promise callers need (or are expected) to await. */
    dispatch(event: string, payload: unknown, opts?: { credentialFields?: string[] }): void;
}
/**
 * For consumers receiving webhook deliveries from this package. Verifies the
 * `X-Idp-Signature` header (`t=<unix seconds>,v1=<hex hmac>`) against the
 * exact raw (unparsed) request body.
 */
/** Pass several secrets during rotation; after verifying, de-duplicate on the body's `id`. */
export function verifyWebhookSignature(secret: string | string[], rawBody: string, signatureHeader: string | undefined, opts?: { toleranceSeconds?: number }): boolean;

// ── Schemas ──────────────────────────────────────────────────────────────

export const schemas: Record<string, { parse: (input: unknown) => unknown }>;

// ── Router convenience ───────────────────────────────────────────────────

export interface BuildRouterOptions {
    /**
     * OAuth2 client administration (`/oauth2/clients*`). NOT mounted unless
     * given; when given, every route runs behind `middleware` (your admin
     * auth). Passing it without at least one middleware throws.
     */
    clientManagement?: { middleware: RequestHandler | RequestHandler[] };
    /** Set a surface to false to leave its routes unmounted. All default to true. */
    features?: Partial<Record<'magicLink' | 'webauthn' | 'sso' | 'oauth2' | 'oidc' | 'serviceMesh', boolean>>;
    /** @deprecated Never had any effect on buildRouter(); accepted and ignored. */
    ownServiceName?: string;
}
export function buildRouter(opts?: BuildRouterOptions): Router;
