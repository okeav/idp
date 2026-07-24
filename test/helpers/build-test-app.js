import crypto from 'crypto';
import express from 'express';
import cookieParserLib from 'cookie-parser';
import { MongoMemoryReplSet } from 'mongodb-memory-server';
import { initIdentityProvider } from '../../src/index.js';
import { buildRouter } from '../../src/routes/build-router.js';
import { getState, setState } from '../../src/config/state.js';

function generateTestSigningKey() {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    return { privateKey, publicKey };
}

/**
 * Boots a real MongoMemoryReplSet (single-node, transactions-capable — see
 * assert-transactions.js) plus a fully-wired Express app on an ephemeral
 * port. One instance is meant to be shared across an entire test file via
 * `before`/`after`; each test uses unique emails to avoid collisions.
 *
 * `hooks` on the returned object is a mutable capture surface — tests read
 * `hooks.calls` to inspect what the package would have sent (verification
 * emails, audit events, etc.) without needing a real mailer.
 */
export async function buildTestApp(overrides = {}) {
    const replSet = await MongoMemoryReplSet.create({ replSet: { count: 1 } });
    const { privateKey, publicKey } = generateTestSigningKey();

    const hookCalls = { onAuditLog: [], onVerificationEmailRequested: [], onPasswordResetRequested: [], onPasswordChanged: [], onSuspiciousActivityDetected: [], onNewDeviceLogin: [], onMagicLinkRequested: [] };
    const hooks = {
        onAuditLog: (e) => hookCalls.onAuditLog.push(e),
        onVerificationEmailRequested: (p) => hookCalls.onVerificationEmailRequested.push(p),
        onPasswordResetRequested: (p) => hookCalls.onPasswordResetRequested.push(p),
        onPasswordChanged: (p) => hookCalls.onPasswordChanged.push(p),
        onSuspiciousActivityDetected: (p) => hookCalls.onSuspiciousActivityDetected.push(p),
        onNewDeviceLogin: (p) => hookCalls.onNewDeviceLogin.push(p),
        onMagicLinkRequested: (p) => hookCalls.onMagicLinkRequested.push(p),
        resolveAuthContext: async () => ({ claims: { role: 'member' } }),
        ...overrides.hooks,
    };

    const silentLogger = { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} };

    const state = await initIdentityProvider({
        issuer: 'https://idp.test.local',
        mongo: { uri: replSet.getUri() },
        cache: { adapter: 'memory' },
        signingKeys: { keys: { 'test-kid-1': { privateKey, publicKey, status: 'ACTIVE' } } },
        security: {
            emailHashPepper: 'test-email-pepper-do-not-use-in-prod',
            tokenHashSecret: 'test-token-hash-secret-do-not-use-in-prod',
            bcryptRounds: 4, // fast for tests
        },
        mfa: { issuerLabel: 'TestApp', recoveryCodeCount: 5 },
        // Disabled by default so the shared test app (used by every *other*
        // test file) isn't coupled to production-tuned thresholds — a test
        // file that specifically wants to exercise rate limiting passes its
        // own `config.rateLimiting` override instead (see rate-limit.test.js).
        rateLimiting: { enabled: false },
        logger: silentLogger,
        hooks,
        ...overrides.config,
    });

    const app = express();
    app.use(cookieParserLib());
    app.use(express.json());
    app.use(express.urlencoded({ extended: false }));
    app.use('/', buildRouter());
    app.use((err, _req, res, _next) => {
        res.status(err.httpStatus || 500).json({ error: err.code || 'INTERNAL_ERROR', message: err.message });
    });

    const server = await new Promise((resolve) => {
        const s = app.listen(0, () => resolve(s));
    });
    const { port } = server.address();
    const baseUrl = `http://127.0.0.1:${port}`;

    return {
        baseUrl,
        state,
        hookCalls,
        async stop() {
            await new Promise((resolve) => server.close(resolve));
            await state.storage.close();
            await replSet.stop();
        },
    };
}

/**
 * `initIdentityProvider()` stores its wired state in a module-level
 * singleton (see src/config/state.js) — by design, since it's what lets
 * every handler export read config without threading it through every call.
 * That means a SECOND `buildTestApp()` call within the same test file
 * clobbers the first one's active state, and simply `stop()`-ing the second
 * app leaves the singleton pointing at a now-closed Mongo connection for
 * any later test in the file that expects the FIRST (shared) app to still
 * be live.
 *
 * Use this whenever a test needs a one-off app with different config
 * alongside a file-level shared `app` from `before()` — it restores
 * whatever state was active before the temporary app was created.
 */
export async function withTemporaryApp(overrides, fn) {
    let previousState = null;
    try {
        previousState = getState();
    } catch {
        // no app initialized yet in this process — nothing to restore afterward
    }

    const temp = await buildTestApp(overrides);
    try {
        return await fn(temp);
    } finally {
        await temp.stop();
        if (previousState) setState(previousState);
    }
}

/** Minimal cookie-jar so tests can carry access_token/refresh_token cookies across requests, like a browser would. */
export function createCookieJar() {
    const jar = new Map();
    return {
        capture(res) {
            const setCookie = res.headers.getSetCookie ? res.headers.getSetCookie() : [];
            for (const raw of setCookie) {
                const [pair] = raw.split(';');
                const idx = pair.indexOf('=');
                jar.set(pair.slice(0, idx), pair.slice(idx + 1));
            }
        },
        header() {
            return [...jar.entries()].map(([k, v]) => `${k}=${v}`).join('; ');
        },
        get(name) {
            return jar.get(name);
        },
        clear() {
            jar.clear();
        },
    };
}

export function uniqueEmail(prefix = 'test') {
    return `${prefix}-${Date.now()}-${Math.floor(Math.random() * 1e6)}@example.com`;
}
