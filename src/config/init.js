import { withDefaults } from './defaults.js';
import { setState } from './state.js';
import { createConsoleLogger } from './console-logger.js';
import { mergeHooks, setHookTimeout } from '../hooks/index.js';
import { createCacheAdapter } from '../cache/index.js';
import { createRateLimiter } from '../rate-limit/index.js';
import { WebhookDispatcher } from '../webhooks/dispatcher.js';
import { wrapHooksWithWebhooks } from '../webhooks/wrap-hooks.js';
import { buildKeyRegistry, assertCanSign } from '../signing/key-registry.js';
import { createMongoStorage } from '../storage/mongo/index.js';
import { makeHashEmail, normalizeEmail } from '../utils/email-hash.js';
import { createMfaSecretCipher, assertMfaSecretConfig } from '../mfa/secrets.js';
import { MemoryAttemptCounterRepository } from '../mfa/memory-attempt-counter.js';
import { prepareDummyHash } from '../utils/password.js';

/**
 * Wires storage, cache, signing keys, hooks, and logger, and stores the
 * result in this module's singleton state. Call once at startup, before
 * mounting any handler/middleware this package exports.
 *
 * @param {import('../../types/index.d.ts').IdpConfig} config
 * @returns {Promise<{ config: object, logger: object, storage: object, cache: object }>}
 *   A read-only-ish view of the wired state, for consumers who want direct
 *   access (e.g. to close the Mongo connection in tests). Every handler
 *   export reads the same underlying state internally — you do not need to
 *   thread this return value through your routes.
 */
export async function initIdentityProvider(config) {
    const resolved = withDefaults(config);

    assertSecurityConfig(resolved.security);
    await prepareDummyHash(resolved.security.bcryptRounds);
    assertRateLimitRules(resolved.rateLimiting);

    const logger = config.logger || createConsoleLogger();

    // MFA secret encryption is validated before anything connects, so a
    // missing key fails the boot rather than the first enrolment.
    const mfaCipher = createMfaSecretCipher(resolved.mfa);
    assertMfaSecretConfig(resolved.mfa, mfaCipher, logger);
    assertLockoutConfig('mfa.lockout', resolved.mfa.lockout);
    assertLockoutConfig('security.verificationCodeLockout', resolved.security.verificationCodeLockout);
    assertLockoutConfig('security.passwordChangeLockout', resolved.security.passwordChangeLockout);
    assertSsoConfig(resolved);
    if (!Number.isInteger(resolved.hookTimeoutMs) || resolved.hookTimeoutMs < 1) throw new Error(`config.hookTimeoutMs must be a positive integer (got ${resolved.hookTimeoutMs})`);
    setHookTimeout(resolved.hookTimeoutMs);
    if (!['all', 'public'].includes(resolved.oauth2.requirePkce)) {
        throw new Error("config.oauth2.requirePkce must be 'all' or 'public'");
    }
    assertCookieConfig(resolved.cookies);
    assertServiceMeshSecrets(resolved.serviceMesh);
    const grace = resolved.serviceMesh.rotationGraceSeconds;
    if (!Number.isInteger(grace) || grace < 0) throw new Error(`config.serviceMesh.rotationGraceSeconds must be an integer >= 0 (got ${grace})`);
    for (const [name, min] of [['recentAuthMaxAgeSeconds', 1], ['absoluteLifetimeSeconds', 1], ['refreshReuseGraceSeconds', 0]]) {
        const value = resolved.session[name];
        if (!Number.isInteger(value) || value < min) throw new Error(`config.session.${name} must be an integer >= ${min} (got ${value})`);
    }
    const webhookDispatcher = new WebhookDispatcher(resolved.webhooks, logger);
    const hooks = wrapHooksWithWebhooks(mergeHooks(resolved.hooks), webhookDispatcher);
    const cache = await createCacheAdapter(resolved.cache);
    const rateLimiter = await createRateLimiter(resolved.rateLimiting, cache.redisClient);
    const signingKeys = buildKeyRegistry(resolved.signingKeys.keys);
    assertCanSign(signingKeys);
    const hashEmail = makeHashEmail(resolved.security.emailHashPepper);

    // Storage is pluggable via `config.storage.factory` — a function with the
    // exact same signature as `createMongoStorage` (config, {hashEmail,
    // normalizeEmail}) => Promise<StorageContract>. This is how a separate
    // adapter package (e.g. a Postgres or DynamoDB adapter) plugs in without
    // idp-core ever importing it — falls back to the built-in Mongo adapter,
    // completely unchanged, when no factory is provided.
    const storage = resolved.storage?.factory
        ? await resolved.storage.factory(resolved, { hashEmail, normalizeEmail })
        : await createMongoStorage(resolved.mongo, { hashEmail, normalizeEmail });

    // Adapters that predate 0.3.0 (or haven't caught up yet) keep working:
    // the MFA lockout falls back to an in-process counter, and per-request
    // session verification falls back to the per-process revocation cache.
    // Both are weaker on a multi-instance deployment, so say so loudly.
    let attemptCounters = storage.attemptCounterRepository;
    if (!attemptCounters) {
        attemptCounters = new MemoryAttemptCounterRepository();
        logger.warn({}, '@okeav/idp-core: storage adapter has no attemptCounterRepository — the per-account MFA lockout is counted in-process only (not shared across instances). Upgrade the adapter.');
    }
    const missingAtomic = ['claimTotpStep', 'consumeRecoveryCode'].filter((m) => typeof storage.userRepository?.[m] !== 'function');
    if (missingAtomic.length > 0) {
        logger.warn({}, `@okeav/idp-core: storage adapter's userRepository has no ${missingAtomic.join('/')}() — TOTP replay and recovery-code reuse are checked with a non-atomic read-then-write, which concurrent requests can race. Upgrade the adapter.`);
    }
    if (resolved.session.verifyOnEachRequest && typeof storage.sessionRepository?.findByJti !== 'function') {
        logger.warn({}, '@okeav/idp-core: session.verifyOnEachRequest is on but the storage adapter\'s sessionRepository has no findByJti() — falling back to the per-process revocation cache, so logout-all/password reset will NOT revoke access tokens before they expire. Upgrade the adapter.');
    }

    const state = { config: resolved, logger, hooks, cache, rateLimiter, webhookDispatcher, signingKeys, storage, hashEmail, normalizeEmail, mfaCipher, attemptCounters };
    setState(state);

    logger.info({ issuer: resolved.issuer }, '@okeav/idp-core initialized');

    return state;
}

/**
 * With any SSO provider configured, the redirect allowlist and the absolute callback base URL are
 * required: SSO without an allowlist is an open redirect at the end of a real provider login, and
 * without baseCallbackUrl the provider is handed a relative redirect_uri it will reject.
 */
function assertSsoConfig(resolved) {
    const configured = Object.entries(resolved.oauthProviders || {}).filter(([, v]) => v?.clientId).map(([k]) => k);
    if (configured.length === 0) return;
    const origins = resolved.sso?.allowedRedirectOrigins;
    if (!Array.isArray(origins) || origins.length === 0) {
        throw new Error(`config.sso.allowedRedirectOrigins is required when SSO providers are configured (${configured.join(', ')}) — list the origins SSO may redirect back to`);
    }
    for (const origin of origins) {
        let url;
        try { url = new URL(origin); } catch { url = null; }
        if (!url || url.origin !== origin) throw new Error(`config.sso.allowedRedirectOrigins: "${origin}" is not an origin (scheme://host[:port], no path)`);
    }
    let base;
    try { base = new URL(resolved.sso?.baseCallbackUrl); } catch { base = null; }
    if (!base || !['https:', 'http:'].includes(base.protocol)) {
        throw new Error('config.sso.baseCallbackUrl must be an absolute URL when SSO providers are configured');
    }
}

const MIN_SECRET_LENGTH = 32;

/**
 * The secrets behind every token hash and the email blind index must be real secrets (a short one
 * can be brute-forced offline from a database dump), and the password-hash cost and lockout numbers
 * must be numbers — a NaN lockout threshold (e.g. from a mistyped env var) silently disables lockout.
 */
function assertSecurityConfig(security) {
    for (const name of ['emailHashPepper', 'tokenHashSecret']) {
        const value = security[name];
        if (!value) throw new Error(`config.security.${name} is required`);
        if (typeof value !== 'string' || value.length < MIN_SECRET_LENGTH) {
            throw new Error(`config.security.${name} must be a random string of at least ${MIN_SECRET_LENGTH} characters`);
        }
    }
    const minRounds = security.allowWeakBcryptRounds === true ? 4 : 10;
    if (!Number.isInteger(security.bcryptRounds) || security.bcryptRounds < minRounds || security.bcryptRounds > 15) {
        throw new Error(`config.security.bcryptRounds must be an integer from ${minRounds} to 15 (got ${security.bcryptRounds})`);
    }
    if (!Number.isInteger(security.maxFailedLoginAttempts) || security.maxFailedLoginAttempts < 1) {
        throw new Error(`config.security.maxFailedLoginAttempts must be a positive integer (got ${security.maxFailedLoginAttempts})`);
    }
    if (!Number.isInteger(security.accountLockDurationMs) || security.accountLockDurationMs < 1000) {
        throw new Error(`config.security.accountLockDurationMs must be an integer of at least 1000 (got ${security.accountLockDurationMs})`);
    }
}

/** Every rate-limit rule needs positive integers — a fractional window can leave Redis keys without a TTL. */
function assertRateLimitRules(rateLimiting) {
    for (const [name, rule] of Object.entries(rateLimiting)) {
        if (!rule || typeof rule !== 'object' || Array.isArray(rule) || !('max' in rule || 'windowSeconds' in rule)) continue;
        if (!Number.isInteger(rule.max) || rule.max < 1 || !Number.isInteger(rule.windowSeconds) || rule.windowSeconds < 1) {
            throw new Error(`config.rateLimiting.${name} needs positive integer max and windowSeconds (got ${JSON.stringify(rule)})`);
        }
    }
}

/**
 * Service-mesh secrets gate who may register a service key (and so mint tokens as that service), or —
 * in tokenMode 'secret'/'both' — who may call as a service: as strong as the token secrets.
 */
function assertServiceMeshSecrets(mesh = {}) {
    const MIN = 32;
    const weak = (v) => typeof v !== 'string' || v.length < MIN;
    for (const key of ['bootstrapSecret', 'sharedSecret']) {
        if (mesh[key] !== undefined && weak(mesh[key])) throw new Error(`config.serviceMesh.${key} must be at least ${MIN} characters`);
    }
    for (const [name, secret] of Object.entries(mesh.bootstrapSecrets ?? {})) {
        if (weak(secret)) throw new Error(`config.serviceMesh.bootstrapSecrets.${name} must be at least ${MIN} characters`);
        if (secret === mesh.bootstrapSecret) throw new Error(`config.serviceMesh.bootstrapSecrets.${name} must differ from the shared bootstrapSecret`);
    }
}

/** A typo in sameSite used to surface as a 500 on every login; SameSite=None without Secure is dropped by browsers. */
function assertCookieConfig(cookies = {}) {
    if (cookies.sameSite !== undefined && !['lax', 'strict', 'none'].includes(cookies.sameSite)) {
        throw new Error(`config.cookies.sameSite must be 'lax', 'strict' or 'none' (got ${JSON.stringify(cookies.sameSite)})`);
    }
    if (cookies.sameSite === 'none' && cookies.secure === false) throw new Error("config.cookies.sameSite 'none' requires secure cookies (browsers drop SameSite=None without Secure)");
    if (cookies.trustedOrigins !== undefined && (!Array.isArray(cookies.trustedOrigins) || cookies.trustedOrigins.some((o) => typeof o !== 'string' || o !== safeOrigin(o)))) {
        throw new Error('config.cookies.trustedOrigins must be an array of exact origins, e.g. https://app.example.com (no path, no trailing slash)');
    }
}

function safeOrigin(value) {
    try {
        return new URL(value).origin;
    } catch {
        return null;
    }
}

function assertLockoutConfig(path, { maxFailedAttempts, windowSeconds, lockSeconds }) {
    for (const [name, value] of Object.entries({ maxFailedAttempts, windowSeconds, lockSeconds })) {
        if (!Number.isInteger(value) || value < 1) throw new Error(`config.${path}.${name} must be a positive integer (got ${value})`);
    }
}
