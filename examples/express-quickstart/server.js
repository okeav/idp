import crypto from 'crypto';
import express from 'express';
import { initIdentityProvider, buildRouter, cookieParser } from '@okeav/idp-core';

// ── Signing key ──────────────────────────────────────────────────────────
// A real deployment generates this once, stores it somewhere durable, and
// passes it in via IDP_SIGNING_KEY_PRIVATE/PUBLIC (base64 PEM — see
// .env.example). This quickstart falls back to generating a throwaway
// keypair at boot so there's nothing to set up to get running — every
// restart invalidates existing sessions since the `kid` changes each time.
let signingKey;
if (process.env.IDP_SIGNING_KEY_PRIVATE && process.env.IDP_SIGNING_KEY_PUBLIC) {
    signingKey = { privateKey: process.env.IDP_SIGNING_KEY_PRIVATE, publicKey: process.env.IDP_SIGNING_KEY_PUBLIC };
} else {
    console.warn('[quickstart] No IDP_SIGNING_KEY_PRIVATE/PUBLIC set — generating an ephemeral RSA keypair for this run only.');
    const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    signingKey = { privateKey, publicKey };
}

await initIdentityProvider({
    issuer: process.env.IDP_ISSUER || 'http://localhost:3000',

    // Matches docker-compose.yml in the repo root: `docker compose up` gets
    // you a single-node Mongo replica set (required for this package's
    // transactions) and a Redis instance on these default ports.
    mongo: { uri: process.env.IDP_MONGO_URI || 'mongodb://localhost:27017/idp-quickstart?replicaSet=rs0' },

    // 'memory' needs zero setup but is single-instance/dev only (see
    // README.md "Cache adapter"). Switch to 'redis' by setting
    // IDP_CACHE_ADAPTER=redis once you're past the quickstart.
    cache: { adapter: process.env.IDP_CACHE_ADAPTER || 'memory', redis: { host: '127.0.0.1', port: 6379 } },

    signingKeys: { keys: { 'quickstart-key-1': { ...signingKey, status: 'ACTIVE' } } },

    security: {
        emailHashPepper: process.env.IDP_EMAIL_HASH_PEPPER || 'quickstart-dev-only-pepper-do-not-use-in-prod',
        tokenHashSecret: process.env.IDP_TOKEN_HASH_SECRET || 'quickstart-dev-only-token-secret-do-not-use-in-prod',
    },

    mfa: { issuerLabel: 'IdpQuickstart' },

    hooks: {
        // No real mailer wired up — print what would have been sent so you
        // can copy the code/link straight out of the terminal.
        onVerificationEmailRequested: ({ email, verificationCode, verificationToken }) => {
            console.log(`[dev email] Verify ${email} — code: ${verificationCode} (or token: ${verificationToken})`);
        },
        onPasswordResetRequested: ({ email, resetToken }) => {
            console.log(`[dev email] Password reset for ${email} — token: ${resetToken}`);
        },
        onAuditLog: (event) => {
            console.log(`[audit] ${event.action}`, event);
        },
        // Every login (password/MFA/SSO) calls this to build the access
        // token's opaque `claims`. A real app resolves role/permissions
        // here from its own data model — this quickstart just hardcodes one.
        resolveAuthContext: async () => ({ claims: { role: 'member' } }),
    },
});

const app = express();
app.use(cookieParser());
app.use(express.json());
app.use('/auth', buildRouter());

// Every error this package throws is an IdpError — map it to your API's
// response shape in exactly one place.
app.use((err, _req, res, _next) => {
    res.status(err.httpStatus || 500).json({ error: err.code || 'INTERNAL_ERROR', message: err.message });
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
    console.log(`Quickstart IDP listening on http://localhost:${port}`);
    console.log(`Try: curl -X POST http://localhost:${port}/auth/register -H "Content-Type: application/json" -d '{"email":"you@example.com","password":"Str0ng!Passw0rd"}'`);
});
