import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import express from 'express';
import { generate as generateTotp } from 'otplib';
import { buildTestApp, uniqueEmail, freshTotp } from './helpers/build-test-app.js';
import { json } from './helpers/serve.js';
import { gate } from './helpers/gate.js';
import { authContextMiddleware, revokeServiceKey } from '../src/index.js';
import { issueMfaChallengeToken, hashOpaqueToken } from '../src/signing/token.service.js';

// Service-key races, client_credentials tokens outliving their client, client registration limits,
// recovery-code strength and MFA challenge audience — from the second review.

const SECRETS = { billing: 'billing-bootstrap-secret-mesh2-0123456789' };
const SHARED = 'shared-bootstrap-secret-mesh2-0123456789';
const ADMIN = { 'x-test-admin': 'yes' };
const password = 'Str0ng!Passw0rd';
let app;
let machine; // a resource server accepting oauth2-client tokens

before(async () => {
    app = await buildTestApp({ config: { serviceMesh: { bootstrapSecrets: SECRETS, bootstrapSecret: SHARED, ownServiceName: 'idp' } } });
    const rs = express();
    rs.get('/x', authContextMiddleware({ accept: ['oauth2-client'] }), (req, res) => res.json({ ok: true }));
    rs.use((err, _req, res, _next) => res.status(err.httpStatus || 500).json({ error: err.code }));
    const server = await new Promise((r) => { const s = rs.listen(0, () => r(s)); });
    machine = { url: `http://127.0.0.1:${server.address().port}/x`, stop: () => new Promise((r) => server.close(r)) };
});

after(async () => {
    await machine.stop();
    await app.stop();
});

const post = (path, body, headers) => fetch(`${app.baseUrl}${path}`, json(body, headers));
const rsa = () => crypto.generateKeyPairSync('rsa', { modulusLength: 2048, publicKeyEncoding: { type: 'spki', format: 'pem' }, privateKeyEncoding: { type: 'pkcs8', format: 'pem' } });
const registerKey = (name, pem, secret) => post('/internal/service-keys', { name, publicKey: Buffer.from(pem).toString('base64') }, { 'x-s2s-bootstrap-secret': secret });
const keys = () => app.state.storage.serviceKeyRepository;

// ── Service keys ─────────────────────────────────────────────────────────────

test('a key revoked while its service is rotating stays revoked', async () => {
    const k0 = (await (await registerKey('billing', rsa().publicKey, SECRETS.billing)).json()).kid;
    const g = gate(keys(), 'listPublishable');
    const rotation = registerKey('billing', rsa().publicKey, SECRETS.billing);
    await g.reached; // the rotation has read k0 as ACTIVE...
    g.restore();
    assert.equal(await revokeServiceKey(k0), true); // ...and k0 is revoked before it demotes it
    g.release();
    assert.equal((await rotation).status, 201);
    assert.equal((await keys().findByKid(k0)).status, 'REVOKED');
});

test('concurrent first registrations of one name with the shared secret: exactly one keeps the name', async () => {
    const name = `svc-${crypto.randomUUID().slice(0, 8)}`;
    const statuses = (await Promise.all([1, 2, 3, 4].map(() => registerKey(name, rsa().publicKey, SHARED)))).map((r) => r.status).sort();
    assert.deepEqual(statuses, [201, 409, 409, 409]);
    const live = (await keys().listPublishable()).filter((k) => k.name === name);
    assert.equal(live.length, 1);
});

test('re-registering a revoked key never demotes the current one, even for a storage adapter without findByKid', async () => {
    const k1 = rsa();
    const kid1 = (await (await registerKey('billing', k1.publicKey, SECRETS.billing)).json()).kid;
    await revokeServiceKey(kid1);
    const kid2 = (await (await registerKey('billing', rsa().publicKey, SECRETS.billing)).json()).kid;
    const findByKid = keys().findByKid;
    keys().findByKid = undefined;
    try {
        assert.equal((await registerKey('billing', k1.publicKey, SECRETS.billing)).status, 409);
    } finally {
        keys().findByKid = findByKid;
    }
    assert.equal((await keys().findByKid(kid2)).status, 'ACTIVE');
});

test('weak service-mesh secrets are refused at startup', async () => {
    await assert.rejects(buildTestApp({ config: { serviceMesh: { bootstrapSecret: 'short' } } }), /bootstrapSecret must be at least 32/);
    await assert.rejects(buildTestApp({ config: { serviceMesh: { bootstrapSecrets: { svc: 'a' } } } }), /bootstrapSecrets\.svc must be at least 32/);
    await assert.rejects(buildTestApp({ config: { serviceMesh: { tokenMode: 'secret', sharedSecret: 'a' } } }), /sharedSecret must be at least 32/);
    const same = 'x'.repeat(40);
    await assert.rejects(buildTestApp({ config: { serviceMesh: { bootstrapSecret: same, bootstrapSecrets: { svc: same } } } }), /must differ/);
});

// ── OAuth2 clients ───────────────────────────────────────────────────────────

async function machineClient() {
    const c = await (await post('/oauth2/clients', {
        name: 'M2M', slug: `m2m-${crypto.randomUUID()}`, redirectUris: ['https://rp.example.com/cb'],
        allowedScopes: ['reports'], allowedGrants: ['client_credentials'],
    }, ADMIN)).json();
    await fetch(`${app.baseUrl}/oauth2/clients/${c.clientId}/approve`, { method: 'POST', headers: ADMIN });
    return c;
}

test('a client_credentials token stops working the moment its client is deactivated', async () => {
    const c = await machineClient();
    const { access_token: token } = await (await post('/oauth2/token', { grant_type: 'client_credentials', client_id: c.clientId, client_secret: c.clientSecret })).json();
    assert.equal((await fetch(machine.url, { headers: { Authorization: `Bearer ${token}` } })).status, 200);
    assert.equal((await fetch(`${app.baseUrl}/oauth2/clients/${c.clientId}`, { method: 'DELETE', headers: ADMIN })).status, 200);
    assert.equal((await fetch(machine.url, { headers: { Authorization: `Bearer ${token}` } })).status, 401);
});

test('client token lifetimes are bounded and display URLs must be https', async () => {
    const c = await machineClient();
    const patch = (body) => fetch(`${app.baseUrl}/oauth2/clients/${c.clientId}`, { method: 'PATCH', headers: { 'Content-Type': 'application/json', ...ADMIN }, body: JSON.stringify(body) });
    assert.equal((await patch({ accessTokenTTL: 10 * 365 * 24 * 3600 })).status, 400);
    assert.equal((await patch({ accessTokenTTL: 3600 })).status, 200);
    for (const field of ['logoUrl', 'websiteUrl', 'privacyPolicyUrl', 'termsOfServiceUrl']) {
        assert.equal((await patch({ [field]: 'javascript:alert(document.cookie)' })).status, 400, field);
        assert.equal((await patch({ [field]: 'data:text/html,<script>1</script>' })).status, 400, field);
    }
    assert.equal((await patch({ websiteUrl: 'https://rp.example.com' })).status, 200);
});

// ── MFA ──────────────────────────────────────────────────────────────────────

async function userWithMfa() {
    const email = uniqueEmail('mfa2');
    await post('/register', { email, password });
    await post('/register/verify-email', { email, code: app.hookCalls.onVerificationEmailRequested.filter((c) => c.email === email).at(-1).verificationCode });
    const login = await (await post('/login', { email, password })).json();
    const auth = { Authorization: `Bearer ${login.accessToken}` };
    const { secret } = await (await fetch(`${app.baseUrl}/me/mfa/setup`, { method: 'POST', headers: auth })).json();
    const confirmed = await (await post('/me/mfa/confirm', { code: await generateTotp({ secret }) }, auth)).json();
    return { email, secret, userId: login.userId, recoveryCodes: confirmed.recoveryCodes };
}

test('recovery codes carry 100 bits, are stored bound to their user, and accept loose typing', async () => {
    const u = await userWithMfa();
    for (const c of u.recoveryCodes) assert.match(c, /^[0-9A-HJKMNP-TV-Z]{5}(-[0-9A-HJKMNP-TV-Z]{5}){3}$/);
    const stored = await app.state.storage.userRepository.findById(u.userId, { select: '+mfaRecoveryCodes' });
    const hashes = stored.mfaRecoveryCodes.map((r) => r.codeHash);
    assert.ok(!hashes.includes(hashOpaqueToken(app.state, u.recoveryCodes[0])), 'not a bare HMAC of the code');

    const challenge = (await (await post('/login', { email: u.email, password })).json()).mfaChallengeToken;
    const typed = ` ${u.recoveryCodes[0].toLowerCase().replace(/-/g, ' ')} `;
    assert.equal((await post('/mfa/verify', { mfaChallengeToken: challenge, code: typed })).status, 200);
});

test('an MFA challenge token from another issuer (sharing the signing key) is refused', async () => {
    const u = await userWithMfa();
    const foreign = await issueMfaChallengeToken({ ...app.state, config: { ...app.state.config, issuer: 'https://staging.other.example' } }, u.userId);
    const res = await post('/mfa/verify', { mfaChallengeToken: foreign, code: await freshTotp(app.state, u.userId, u.secret) });
    assert.equal(res.status, 401);
});
