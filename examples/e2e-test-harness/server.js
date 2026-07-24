import crypto from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';
import express from 'express';
import cookieParser from 'cookie-parser';
import { initIdentityProvider, buildRouter, verifyWebhookSignature } from '@okeav/idp-core';

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
const WEBHOOK_SECRET = 'harness-webhook-secret-do-not-use-in-prod';
const BOOTSTRAP_SECRET = 'harness-s2s-bootstrap-secret-do-not-use-in-prod';

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
    security: {
        emailHashPepper: 'harness-dev-only-email-pepper',
        tokenHashSecret: 'harness-dev-only-token-hash-secret',
        bcryptRounds: 4, // fast — this is a click-through harness, not a security benchmark
        // Deliberately very high: flow #12 exists specifically to demonstrate
        // *rate limiting* (request-rate throttling) as a distinct mechanism
        // from account lockout (failed-attempt counting) — raising this out
        // of the way keeps the two from being conflated on screen.
        maxFailedLoginAttempts: 1000,
    },
    mfa: { issuerLabel: 'IdpE2EHarness' },
    magicLink: { allowSignupViaMagicLink: true },
    // rpID 'localhost' + an http:// origin is the one case the WebAuthn spec
    // carves out as a valid secure context without HTTPS — exactly what lets
    // flow #8 run over plain `npm start` with no cert setup.
    webauthn: { rpID: 'localhost', rpName: 'IdpE2EHarness', origin: BASE_URL },
    oauthProviders: googleClientId ? { google: { clientId: googleClientId, clientSecret: googleClientSecret } } : {},
    sso: { baseCallbackUrl: IDP_BASE_URL, allowedRedirectOrigins: [BASE_URL] },
    serviceMesh: { bootstrapSecret: BOOTSTRAP_SECRET, tokenMode: 'both' },
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
    },
    // Pre-configured at boot, pointed at this same process's own receiver
    // (below) — webhooks are a deploy-time config in real usage, not
    // something registered through a runtime API, so this is exactly how a
    // real consumer would set it up too. See flow #13.
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

    recordWebhookDelivery({ event, deliveryId, signatureHeader, valid, rawBody, receivedAt: new Date().toISOString() });
    pushActivity('webhook', `delivery received: ${event} — signature ${valid ? 'VALID' : 'INVALID'}`, { event, deliveryId, valid });

    res.status(200).json({ received: true });
});

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// idp-core's own router — every /auth/* route is the exact same public
// surface a real consumer mounts, untouched.
app.use(AUTH_PREFIX, buildRouter());

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
    BOOTSTRAP_SECRET,
    WEBHOOK_SECRET,
    googleConfigured: Boolean(googleClientId),
});

// Every error idp-core throws is an IdpError — same one-place mapping the
// main README's quickstart shows, so the harness is itself a real (if
// minimal) example of consuming it.
app.use((err, _req, res, _next) => {
    pushActivity('error', `${err.code || 'INTERNAL_ERROR'} (${err.httpStatus || 500})`, err.message);
    res.status(err.httpStatus || 500).json({ error: err.code || 'INTERNAL_ERROR', message: err.message });
});

app.listen(PORT, () => {
    console.log(`\nidp-core test harness listening on ${BASE_URL}`);
    console.log(`Open ${BASE_URL} in a browser and click through README.md's checklist.\n`);
});
