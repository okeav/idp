import crypto from 'crypto';
import express from 'express';
import { initIdentityProvider, buildRouter, cookieParser, idpErrorHandler } from '@okeav/idp-core';

// This quickstart falls back to throwaway dev values for anything not set in the environment.
// Those values are public (they're in this file), so outside development every one of them must
// be set — refuse to start rather than run with known keys.
// Dev fallbacks only with NODE_ENV=development, said explicitly: an unset NODE_ENV (common in containers)
// is treated as production — by this file and by idp-core's cookie defaults alike.
const isDevelopment = process.env.NODE_ENV === 'development';
function devFallback(name, value) {
    if (process.env[name]) return process.env[name];
    if (!isDevelopment) throw new Error(`[quickstart] ${name} must be set unless NODE_ENV=development — the dev fallback is public`);
    console.warn(`[quickstart] ${name} not set — using a DEV-ONLY value`);
    return value;
}

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
    if (!isDevelopment) throw new Error('[quickstart] IDP_SIGNING_KEY_PRIVATE/PUBLIC must be set unless NODE_ENV=development');
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
        emailHashPepper: devFallback('IDP_EMAIL_HASH_PEPPER', 'quickstart-dev-only-pepper-do-not-use-in-prod'),
        tokenHashSecret: devFallback('IDP_TOKEN_HASH_SECRET', 'quickstart-dev-only-token-secret-do-not-use-in-prod'),
    },

    // 0.3.0+: TOTP secrets are encrypted at rest and a key is required at
    // startup. Dev-only fallback key — set IDP_MFA_ENCRYPTION_KEY
    // (`openssl rand -base64 32`) for anything real.
    mfa: {
        issuerLabel: 'IdpQuickstart',
        encryptionKey: devFallback('IDP_MFA_ENCRYPTION_KEY', Buffer.alloc(32, 0x51).toString('base64')),
    },

    hooks: {
        // No real mailer wired up — print what would have been sent so you
        // can copy the code/link straight out of the terminal.
        // verificationCode is null once the address has had 3 codes in the code's lifetime —
        // a real email then carries only the link (verificationToken).
        onVerificationEmailRequested: ({ email, verificationCode, verificationToken }) => {
            console.log(`[dev email] Verify ${email} — ${verificationCode ? `code: ${verificationCode} (or token: ${verificationToken})` : `link only — token: ${verificationToken}`}`);
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

// Answers IdpErrors with { error, message } and everything else with a bare 500 — never an internal
// message, stack trace or database detail. (Write your own handler if your API needs another shape,
// but keep that rule: only show `message` for an IdpError with httpStatus < 500.)
app.use(idpErrorHandler({ logger: console }));

const port = process.env.PORT || 3000;
app.listen(port, () => {
    console.log(`Quickstart IDP listening on http://localhost:${port}`);
    console.log(`Try: curl -X POST http://localhost:${port}/auth/register -H "Content-Type: application/json" -d '{"email":"you@example.com","password":"Str0ng!Passw0rd"}'`);
});
