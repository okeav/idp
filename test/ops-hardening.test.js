import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import express from 'express';
import { buildTestApp, withTemporaryApp, uniqueEmail } from './helpers/build-test-app.js';
import { json } from './helpers/serve.js';
import { configFromEnv, idpErrorHandler, ERROR_CODES } from '../src/index.js';
import { remoteJwksKeyLookup } from '../src/service-mesh/remote-jwks-key-lookup.js';
import { initServiceIdentity } from '../src/service-mesh/service-identity.client.js';

// Logging, startup validation and smaller fixes — from the second review.

const password = 'Str0ng!Passw0rd';

function captureLogger() {
    const lines = [];
    const log = (level) => (obj, msg) => lines.push({ level, obj, msg, text: JSON.stringify({ obj, msg }, (_k, v) => (v instanceof Error ? { name: v.name, message: v.message, stack: v.stack } : v)) });
    return { lines, logger: { debug: log('debug'), info: log('info'), warn: log('warn'), error: log('error') } };
}

test('rejected and failed requests are logged by path, never with their query string', async () => {
    const { lines, logger } = captureLogger();
    await withTemporaryApp({ config: { logger } }, async (temp) => {
        await fetch(`${temp.baseUrl}/me?id_token_hint=SECRET-IN-QUERY`, { headers: { Authorization: 'Bearer not-a-jwt' } });
        const rejected = lines.find((l) => l.msg === 'authContextMiddleware rejected request');
        assert.ok(rejected);
        assert.equal(rejected.obj.path, '/me');
        assert.ok(!lines.some((l) => l.text.includes('SECRET-IN-QUERY')));
    });
});

test('idpErrorHandler without a logger logs 5xx errors through the configured one', async () => {
    const { lines, logger } = captureLogger();
    await withTemporaryApp({ config: { logger } }, async () => {
        const app = express();
        app.get('/boom', () => { throw new Error('kaboom'); });
        app.use(idpErrorHandler());
        const server = await new Promise((r) => { const s = app.listen(0, () => r(s)); });
        try {
            const res = await fetch(`http://127.0.0.1:${server.address().port}/boom?secret=QUERY-SECRET`);
            assert.equal(res.status, 500);
        } finally {
            await new Promise((r) => server.close(r));
        }
        const logged = lines.find((l) => l.msg === 'Unhandled error');
        assert.ok(logged, 'logged');
        assert.equal(logged.obj.path, '/boom');
        assert.ok(!logged.text.includes('QUERY-SECRET'));
    });
});

test('a throwing hook is logged by name and message only — not the payload its error carries', async () => {
    const { lines, logger } = captureLogger();
    const mailerError = () => Object.assign(new Error('mailer rejected the request'), { config: { data: 'leaked-token' } });
    await withTemporaryApp({ config: { logger }, hooks: { onMagicLinkRequested: (p) => { throw Object.assign(mailerError(), { config: { data: p.magicLinkToken } }); } } }, async (temp) => {
        await fetch(`${temp.baseUrl}/magic-link/request`, json({ email: uniqueEmail('hook-log') }));
        await new Promise((r) => setTimeout(r, 50));
        const warned = lines.find((l) => /threw/.test(l.msg ?? ''));
        assert.ok(warned);
        assert.equal(warned.obj.err.message, 'mailer rejected the request');
        assert.equal(warned.obj.err.config, undefined);
    });
});

test('unsafe configuration is refused at startup', async () => {
    const cases = [
        [{ issuer: 'http://idp.example.com' }, /issuer must be an https URL/],
        [{ issuer: 'not a url' }, /issuer must be an https URL/],
        [{ ttls: { refreshToken: -1 } }, /ttls\.refreshToken must be a positive integer/],
        [{ ttls: { accessToken: 1.5 } }, /ttls\.accessToken must be a positive integer/],
        [{ session: { verifyOnEachRequest: false }, ttls: { accessToken: 3600, revocationCache: 60 } }, /revocationCache must be at least/],
        [{ sso: { baseCallbackUrl: 'http://idp.example.com/auth', allowedRedirectOrigins: ['https://app.example.com'] }, oauthProviders: { google: { clientId: 'x', clientSecret: 'y' } } }, /baseCallbackUrl must be https/],
    ];
    for (const [config, error] of cases) await assert.rejects(buildTestApp({ config }), error, JSON.stringify(config));
    const same = 'z'.repeat(48);
    await assert.rejects(buildTestApp({ config: { security: { tokenHashSecret: same, emailHashPepper: same, bcryptRounds: 4, allowWeakBcryptRounds: true } } }), /must be different secrets/);
});

test('http to a loopback issuer is fine (development)', async () => {
    const temp = await buildTestApp({ config: { issuer: 'http://localhost:3000' } });
    await temp.stop();
});

test('service-mesh clients refuse a plain-http IdP URL (except localhost)', async () => {
    assert.throws(() => remoteJwksKeyLookup('http://idp.example.com'), /must be https/);
    assert.doesNotThrow(() => remoteJwksKeyLookup('http://127.0.0.1:4000'));
    const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048, privateKeyEncoding: { type: 'pkcs8', format: 'pem' }, publicKeyEncoding: { type: 'spki', format: 'pem' } });
    await assert.rejects(initServiceIdentity({ serviceName: 'svc', privateKeyPem: privateKey, idpBaseUrl: 'http://idp.example.com', bootstrapSecret: 'x'.repeat(40) }), /must be https/);
});

test('configFromEnv decodes the base64 Apple private key', () => {
    const pem = '-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n';
    const c = configFromEnv({ IDP_SSO_APPLE_CLIENT_ID: 'id', IDP_SSO_APPLE_TEAM_ID: 't', IDP_SSO_APPLE_KEY_ID: 'k', IDP_SSO_APPLE_PRIVATE_KEY_B64: Buffer.from(pem).toString('base64') });
    assert.equal(c.oauthProviders.apple.privateKeyPem, pem);
});

test('the error-code catalogue lists the codes added in 0.4.0', () => {
    for (const code of ['COOKIE_CONFLICT', 'REGISTRATION_PASSWORD_REQUIRED', 'PASSWORD_CHANGE_LOCKED', 'SERVICE_KEY_REVOKED', 'CSRF_ORIGIN_REJECTED']) {
        assert.equal(ERROR_CODES[code], code);
    }
});

test('GET /me reports a pre-0.4.0 automatic lock as the active account it is', async () => {
    const temp = await buildTestApp();
    try {
        const email = uniqueEmail('me-legacy');
        await fetch(`${temp.baseUrl}/register`, json({ email, password }));
        await fetch(`${temp.baseUrl}/register/verify-email`, json({ email, code: temp.hookCalls.onVerificationEmailRequested.filter((c) => c.email === email).at(-1).verificationCode }));
        const login = await (await fetch(`${temp.baseUrl}/login`, json({ email, password }))).json();
        await temp.state.storage.userRepository.updateById(login.userId, { status: 'LOCKED', lockUntil: new Date(Date.now() + 60_000) });
        const me = await (await fetch(`${temp.baseUrl}/me`, { headers: { Authorization: `Bearer ${login.accessToken}` } })).json();
        assert.equal(me.status, 'ACTIVE');
        assert.equal(me.isActive, true);
    } finally {
        await temp.stop();
    }
});
