import { withDefaults } from './defaults.js';
import { setState } from './state.js';
import { createConsoleLogger } from './console-logger.js';
import { mergeHooks } from '../hooks/index.js';
import { createCacheAdapter } from '../cache/index.js';
import { createRateLimiter } from '../rate-limit/index.js';
import { WebhookDispatcher } from '../webhooks/dispatcher.js';
import { wrapHooksWithWebhooks } from '../webhooks/wrap-hooks.js';
import { buildKeyRegistry } from '../signing/key-registry.js';
import { createMongoStorage } from '../storage/mongo/index.js';
import { makeHashEmail, normalizeEmail } from '../utils/email-hash.js';

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

    if (!resolved.security.emailHashPepper) throw new Error('config.security.emailHashPepper is required');
    if (!resolved.security.tokenHashSecret) throw new Error('config.security.tokenHashSecret is required');

    const logger = config.logger || createConsoleLogger();
    const webhookDispatcher = new WebhookDispatcher(resolved.webhooks, logger);
    const hooks = wrapHooksWithWebhooks(mergeHooks(resolved.hooks), webhookDispatcher);
    const cache = await createCacheAdapter(resolved.cache);
    const rateLimiter = await createRateLimiter(resolved.rateLimiting, cache.redisClient);
    const signingKeys = buildKeyRegistry(resolved.signingKeys.keys);
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

    const state = { config: resolved, logger, hooks, cache, rateLimiter, webhookDispatcher, signingKeys, storage, hashEmail, normalizeEmail };
    setState(state);

    logger.info({ issuer: resolved.issuer }, '@okeav/idp-core initialized');

    return state;
}
