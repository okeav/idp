import crypto from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';
import express from 'express';
import cookieParser from 'cookie-parser';
import { initIdentityProvider, buildRouter, authContextMiddleware, verifyWebhookSignature, idpErrorHandler, serviceContextMiddleware, requireServiceCallerMiddleware } from '@okeav/idp-core';

import { pushActivity, getActivitySince } from './lib/activity-log.js';
import { recordDevToken, latestDevToken } from './lib/dev-store.js';
import { recordWebhookDelivery, getWebhookDeliveries } from './lib/webhook-store.js';
import { mountFlowRoutes } from './routes/index.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const PORT = Number(process.env.PORT || 3100);
const BASE_URL = `http://localhost:${PORT}`;
const AUTH_PREFIX = '/auth';
const IDP_BASE_URL = `${BASE_URL}${AUTH_PREFIX}`;

// Dev-only fixed secrets — a real deployment generates/stores these properly
// (see idp-core's own README "Configuration" section). Fine to hardcode here
// since this harness's whole Mongo/Redis dataset is throwaway.
const WEBHOOK_SECRET = 'harness-webhook-secret-do-not-use-in-prod'; // >= 16 chars (checked at startup)
// Service mesh (flow 11): one bootstrap secret PER SERVICE — each proves which
// service is registering, and lets that service rotate its own key. The
// shared secret is kept only so flow 11 can demonstrate its limits: it can
// NOT register a name that has its own secret (403 FORBIDDEN), and for a
// name without one (LEGACY_SERVICE_NAME) it can claim the name once but
// never replace that key (409 SERVICE_NAME_TAKEN).
const SERVICE_BOOTSTRAP_SECRETS = {
    'harness-service-a': 'harness-s2s-bootstrap-secret-service-a-dev-only',
    'harness-service-b': 'harness-s2s-bootstrap-secret-service-b-dev-only',
};
const SHARED_BOOTSTRAP_SECRET = 'harness-s2s-shared-bootstrap-secret-do-not-use-in-prod';
const LEGACY_SERVICE_NAME = 'harness-legacy-service'; // allowed, but has no per-service secret
// TOTP secrets are encrypted at rest and idp-core refuses to boot without a
// key while MFA is enabled. Fixed (not regenerated per boot like the signing
// key below) because enrolled users' secrets live in the persistent Mongo
// volume — a new key every restart would make them unreadable.
const MFA_ENCRYPTION_KEY = process.env.IDP_MFA_ENCRYPTION_KEY
    || crypto.createHash('sha256').update('harness-dev-only-mfa-encryption-key').digest('base64'); // 32 bytes

// Ephemeral RSA signing keypair — every restart invalidates existing
// sessions (the `kid` changes), which is fine for a manual test harness.
const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

const googleClientId = process.env.GOOGLE_CLIENT_ID;
const googleClientSecret = process.env.GOOGLE_CLIENT_SECRET;
if (!googleClientId) {
    console.warn('[harness] GOOGLE_CLIENT_ID/GOOGLE_CLIENT_SECRET not set — flow #10 (SSO) will show as unconfigured. See README.md for what to supply.');
}

await initIdentityProvider({
    issuer: BASE_URL,
    mongo: { uri: process.env.IDP_MONGO_URI || 'mongodb://localhost:27017/idp-e2e-harness?replicaSet=rs0' },
    cache: { adapter: 'memory' },
    signingKeys: { keys: { 'harness-key-1': { privateKey, publicKey, status: 'ACTIVE' } } },
    // The UI pages are served by this same process, so they're same-origin
    // with `issuer` and pass idp-core's CSRF origin check on cookie-
    // authenticated POSTs without any extra config. If you ever serve the
    // pages from another origin, list it here.
    //
    // refreshTokenInBody: true — the harness pages display the refresh token
    // and flow #3 pastes it back. The default ('auto') leaves it out of the
    // JSON body for browser requests, keeping it in the httpOnly cookie only;
    // a real browser app should keep that default.
    cookies: { trustedOrigins: [BASE_URL], refreshTokenInBody: true },
    security: {
        // idp-core refuses to boot with either of these under 32 characters.
        emailHashPepper: 'harness-dev-only-email-hash-pepper-not-secret',
        tokenHashSecret: 'harness-dev-only-token-hash-secret-not-secret',
        bcryptRounds: 4, // fast — this is a click-through harness, not a security benchmark
        allowWeakBcryptRounds: true, // required for anything under 10 rounds (tests/harnesses only)
        // Deliberately very high: flow #12 exists specifically to demonstrate
        // *rate limiting* (request-rate throttling) as a distinct mechanism
        // from the password-login lockout (failed-attempt counting) — raising this out
        // of the way keeps the two from being conflated on screen.
        maxFailedLoginAttempts: 1000,
    },
    mfa: { issuerLabel: 'IdpE2EHarness', encryptionKey: MFA_ENCRYPTION_KEY },
    magicLink: { allowSignupViaMagicLink: true },
    // rpID 'localhost' + an http:// origin is the one case the WebAuthn spec
    // carves out as a valid secure context without HTTPS — exactly what lets
    // flow #8 run over plain `npm start` with no cert setup.
    webauthn: { rpID: 'localhost', rpName: 'IdpE2EHarness', origin: BASE_URL },
    oauthProviders: googleClientId ? { google: { clientId: googleClientId, clientSecret: googleClientSecret } } : {},
    // Required (exact origins + absolute callback base) whenever an SSO provider is configured.
    sso: { baseCallbackUrl: IDP_BASE_URL, allowedRedirectOrigins: [BASE_URL] },
    serviceMesh: {
        bootstrapSecrets: SERVICE_BOOTSTRAP_SECRETS,
        bootstrapSecret: SHARED_BOOTSTRAP_SECRET,
        allowedServiceNames: [...Object.keys(SERVICE_BOOTSTRAP_SECRETS), LEGACY_SERVICE_NAME],
        tokenMode: 'token', // the default since 0.4.0 — signed S2S tokens only
        ownServiceName: 'harness-service-a', // the `aud` serviceContextMiddleware expects (flow 11, step 6)
    },
    // Low, fast-to-trip thresholds on purpose — this is what flow #12 clicks
    // through in real time. Production defaults are documented in idp-core's
    // own README ("Rate limiting").
    rateLimiting: {
        enabled: true,
        login: { max: 8, windowSeconds: 300 },
        loginByEmail: { max: 5, windowSeconds: 300 },
        passwordReset: { max: 3, windowSeconds: 300 },
        mfaChallenge: { max: 5, windowSeconds: 300 },
        refreshToken: { max: 30, windowSeconds: 60 },
        magicLink: { max: 3, windowSeconds: 300 },
        // Raised above the production defaults (10/hour per IP) only so
        // repeated click-throughs of flows 1 and 13 don't trip it.
        register: { max: 50, windowSeconds: 3600 },
    },
    // Pre-configured at boot, pointed at this same process's own receiver
    // (below) — webhooks are a deploy-time config in real usage, not
    // something registered through a runtime API, so this is exactly how a
    // real consumer would set it up too. See flow #13.
    // No `includeCredentials`: this receiver is an "event analytics" style
    // endpoint, so idp-core strips reset tokens / magic-link tokens /
    // verification codes from its deliveries (the in-process hooks below
    // still get them). Flow 13 shows that they're absent.
    webhooks: { endpoints: [{ url: `${BASE_URL}/webhooks/receiver`, secret: WEBHOOK_SECRET }], maxAttempts: 3, retryBaseDelayMs: 300 },
    logger: console,
    hooks: {
        onAuditLog: (event) => pushActivity('hook', `onAuditLog: ${event.action}`, event),
        onVerificationEmailRequested: (p) => { recordDevToken(p.email, 'verification', p); pushActivity('hook', 'onVerificationEmailRequested (dev-mode — no real email sent)', p); },
        onPasswordResetRequested: (p) => { recordDevToken(p.email, 'password-reset', p); pushActivity('hook', 'onPasswordResetRequested (dev-mode — no real email sent)', p); },
        onPasswordChanged: (p) => pushActivity('hook', 'onPasswordChanged', p),
        onSuspiciousActivityDetected: (p) => pushActivity('hook', 'onSuspiciousActivityDetected', p),
        onNewDeviceLogin: (p) => pushActivity('hook', 'onNewDeviceLogin', p),
        onMagicLinkRequested: (p) => { recordDevToken(p.email, 'magic-link', p); pushActivity('hook', 'onMagicLinkRequested (dev-mode — no real email sent)', p); },
        // A real app resolves role/permissions/tenant from its own data
        // model here — this harness just tags which login method fired it,
        // so you can see resolveAuthContext actually running per flow.
        resolveAuthContext: async (user, ctx) => ({ claims: { role: 'member', via: ctx?.method || ctx?.provider || 'unknown' } }),
    },
});

const app = express();
app.use(cookieParser());

// Registered BEFORE the global express.json() below so this route sees the
// exact raw request body — HMAC verification needs the untouched bytes, not
// a re-serialized JSON.parse/stringify round trip of them.
app.post('/webhooks/receiver', express.raw({ type: '*/*' }), (req, res) => {
    const rawBody = req.body.toString('utf8');
    const signatureHeader = req.header('x-idp-signature');
    const event = req.header('x-idp-event');
    const deliveryId = req.header('x-idp-delivery');
    const valid = verifyWebhookSignature(WEBHOOK_SECRET, rawBody, signatureHeader);
    // Since 0.4.0 the delivery id is also inside the SIGNED body (`id`) — a
    // real receiver de-duplicates on that one, not the unsigned header.
    let bodyId = null;
    let credentialFieldsPresent = [];
    try {
        const parsed = JSON.parse(rawBody);
        bodyId = parsed?.id ?? null;
        const data = parsed?.payload;
        credentialFieldsPresent = ['resetToken', 'magicLinkToken', 'verificationToken', 'verificationCode'].filter((k) => data && typeof data === 'object' && k in data);
    } catch { /* not JSON — recorded as-is below */ }

    recordWebhookDelivery({ event, deliveryId, bodyId, credentialFieldsPresent, signatureHeader, valid, rawBody, receivedAt: new Date().toISOString() });
    pushActivity('webhook', `delivery received: ${event} — signature ${valid ? 'VALID' : 'INVALID'}`, { event, deliveryId, bodyId, valid, credentialFieldsPresent });

    res.status(200).json({ received: true });
});

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// idp-core's own router — every /auth/* route is the exact same public
// surface a real consumer mounts, untouched. OAuth2 client administration
// (/oauth2/clients*, flow 9) is only mounted behind the consumer's own admin
// middleware. idp-core has no admin-role concept, so in this harness any
// logged-in user counts as an admin; a real app checks its own admin claim here.
const harnessAdmin = [
    authContextMiddleware(),
    (req, _res, next) => {
        pushActivity('hook', `clientManagement middleware: ${req.method} ${req.originalUrl} allowed (harness treats any logged-in user as admin)`, { userId: req.auth.userId });
        next();
    },
];
app.use(AUTH_PREFIX, buildRouter({ clientManagement: { middleware: harnessAdmin } }));

// Flow 11, step 6: an internal endpoint "owned" by harness-service-a, as a
// service running idp-core in-process would protect it. serviceContextMiddleware
// checks the caller's signed S2S token against the registered keys, with
// aud = config.serviceMesh.ownServiceName ('harness-service-a');
// requireServiceCallerMiddleware then pins the allowed caller names.
app.get('/internal-demo/service-a/whoami',
    serviceContextMiddleware(),
    requireServiceCallerMiddleware('harness-service-b'),
    (req, res) => res.json({ servedBy: 'harness-service-a', caller: req.serviceCaller }));

// Harness-only plumbing (not part of idp-core) ---------------------------
app.get('/api/activity', (req, res) => {
    res.json(getActivitySince(Number(req.query.since) || 0));
});
app.get('/api/dev-token', (req, res) => {
    const { email, kind } = req.query;
    res.json(latestDevToken(String(email || ''), String(kind || '')));
});
app.get('/api/webhook-deliveries', (req, res) => {
    res.json(getWebhookDeliveries());
});
app.post('/api/totp/compute', async (req, res) => {
    const { generate } = await import('otplib');
    const code = await generate({ secret: req.body.secret, strategy: 'totp' });
    res.json({ code });
});

mountFlowRoutes(app, {
    BASE_URL,
    AUTH_PREFIX,
    IDP_BASE_URL,
    SERVICE_BOOTSTRAP_SECRETS,
    SHARED_BOOTSTRAP_SECRET,
    LEGACY_SERVICE_NAME,
    WEBHOOK_SECRET,
    googleConfigured: Boolean(googleClientId),
});

// Every error idp-core throws is an IdpError. The first handler only mirrors
// it into the activity panel; idp-core's own `idpErrorHandler()` then answers
// — `{ error, message }` for client errors, a bare 500 (no internals) for
// anything else — which is what a real consumer should mount too.
app.use((err, _req, _res, next) => {
    pushActivity('error', `${err.code || 'INTERNAL_ERROR'} (${err.httpStatus || err.status || 500})`, err.message);
    next(err);
});
app.use(idpErrorHandler({ logger: console }));

// Loopback only: this harness hands out any user's reset / verification tokens (/api/dev-token) and every
// hook payload (/api/activity) to whoever asks — never expose it to the network.
app.listen(PORT, '127.0.0.1', () => {
    console.log(`\nidp-core test harness listening on ${BASE_URL}`);
    console.log(`Open ${BASE_URL} in a browser and click through README.md's checklist.\n`);
});
