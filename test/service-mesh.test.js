import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import http from 'http';
import express from 'express';
import jwt from 'jsonwebtoken';
import { buildTestApp, withTemporaryApp } from './helpers/build-test-app.js';
import { json } from './helpers/serve.js';
import { serviceContextMiddleware, requireServiceCallerMiddleware, revokeServiceKey, verifyServiceTokenRemote } from '../src/index.js';
import { remoteJwksKeyLookup } from '../src/service-mesh/remote-jwks-key-lookup.js';

// Service-mesh issues found in the 0.3.0 audit:
//  - one shared bootstrap secret could register a key under ANY service name
//    (impersonation), and keys could never be revoked;
//  - tokenMode 'both' (the default) fell back to a shared secret with a
//    self-declared x-service-name, and a missing ownServiceName silently did too;
//  - service tokens without exp (or living for years) were accepted;
//  - weak/EC/private keys were accepted at registration;
//  - unknown kids forced a JWKS refetch on every request, with no timeout.

const SECRETS = { billing: 'billing-bootstrap-secret-0001', orders: 'orders-bootstrap-secret-0002' };
const SHARED = 'shared-bootstrap-secret-0003';
let app;
let probe; // an internal endpoint guarded by serviceContextMiddleware + requireServiceCallerMiddleware('billing')

const rsa = (bits = 2048) => crypto.generateKeyPairSync('rsa', { modulusLength: bits, publicKeyEncoding: { type: 'spki', format: 'pem' }, privateKeyEncoding: { type: 'pkcs8', format: 'pem' } });
const b64 = (pem) => Buffer.from(pem, 'utf8').toString('base64');

before(async () => {
    app = await buildTestApp({ config: { serviceMesh: { bootstrapSecrets: SECRETS, bootstrapSecret: SHARED, ownServiceName: 'idp', sharedSecret: 'legacy-shared-secret' } } });
    const p = express();
    p.get('/ping', serviceContextMiddleware(), requireServiceCallerMiddleware('billing'), (req, res) => res.json(req.serviceCaller));
    p.use((err, _req, res, _next) => res.status(err.httpStatus || 500).json({ error: err.code || 'INTERNAL_ERROR' }));
    const server = await new Promise((r) => { const s = p.listen(0, () => r(s)); });
    probe = { url: `http://127.0.0.1:${server.address().port}/ping`, stop: () => new Promise((r) => server.close(r)) };
});

after(async () => {
    await probe.stop();
    await app.stop();
});

const register = (name, publicKeyPem, secret, base = app.baseUrl) => fetch(`${base}/internal/service-keys`, json({ name, publicKey: b64(publicKeyPem) }, { 'x-s2s-bootstrap-secret': secret }));

function mint(privateKey, kid, claims = {}, { noExp = false } = {}) {
    const now = Math.floor(Date.now() / 1000);
    const payload = { iss: 'billing', aud: 'idp', iat: now, ...(noExp ? {} : { exp: now + 60 }), jti: crypto.randomUUID(), ...claims };
    return jwt.sign(payload, privateKey, { algorithm: 'RS256', keyid: kid });
}
const ping = (headers) => fetch(probe.url, { headers });

let billing; // { privateKey, kid }

test('a per-service bootstrap secret registers exactly its own name', async () => {
    const k = rsa();
    const ok = await register('billing', k.publicKey, SECRETS.billing);
    assert.equal(ok.status, 201, await ok.clone().text());
    billing = { privateKey: k.privateKey, kid: (await ok.json()).kid };

    const other = await register('orders', rsa().publicKey, SECRETS.billing);
    assert.equal(other.status, 401, 'billing\'s secret does not cover orders');
    assert.equal((await register('billing', rsa().publicKey, 'wrong-secret')).status, 401);
});

test('the shared bootstrap secret cannot replace an existing service\'s key (no impersonation)', async () => {
    const attacker = rsa();
    const res = await register('billing', attacker.publicKey, SHARED);
    assert.equal(res.status, 409);
    assert.equal((await res.json()).error, 'SERVICE_NAME_TAKEN');

    // A token signed with the attacker's key isn't accepted as billing.
    const forged = mint(attacker.privateKey, 'billing:attacker');
    assert.equal((await ping({ Authorization: `Bearer ${forged}` })).status, 401);

    // It can still register a brand-new name, and re-registering the same key is idempotent.
    const k = rsa();
    assert.equal((await register('reports', k.publicKey, SHARED)).status, 201);
    assert.equal((await register('reports', k.publicKey, SHARED)).status, 201);
});

test('a valid service token passes; the caller allowlist is enforced', async () => {
    const res = await ping({ Authorization: `Bearer ${mint(billing.privateKey, billing.kid)}` });
    assert.equal(res.status, 200, await res.clone().text());
    assert.equal((await res.json()).name, 'billing');
});

test('service tokens must expire, live at most 5 minutes, not be issued in the future, and name their key\'s owner', async () => {
    const now = Math.floor(Date.now() / 1000);
    const cases = {
        'no exp': mint(billing.privateKey, billing.kid, {}, { noExp: true }),
        'ten-year exp': mint(billing.privateKey, billing.kid, { exp: now + 10 * 365 * 86400 }),
        'iat in the future': mint(billing.privateKey, billing.kid, { iat: now + 3600, exp: now + 3660 }),
        'old iat': mint(billing.privateKey, billing.kid, { iat: now - 3600, exp: now + 60 }),
        'iss is not the key owner': mint(billing.privateKey, billing.kid, { iss: 'orders' }),
        'wrong audience': mint(billing.privateKey, billing.kid, { aud: 'someone-else' }),
    };
    for (const [why, token] of Object.entries(cases)) {
        assert.equal((await ping({ Authorization: `Bearer ${token}` })).status, 401, why);
    }
});

test('registration accepts only RSA public keys of at least 2048 bits, and well-formed names', async () => {
    const k = rsa();
    const cases = [
        ['a private key', 'orders', k.privateKey],
        ['a 1024-bit key', 'orders', rsa(1024).publicKey],
        ['an EC key', 'orders', crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({ type: 'spki', format: 'pem' })],
        ['garbage', 'orders', 'not a key'],
        ['a bad name', 'Orders Service!', k.publicKey],
    ];
    for (const [why, name, pem] of cases) {
        const secret = SECRETS[name] ?? SHARED;
        const res = await register(name, pem, secret);
        assert.equal(res.status, 400, why);
    }
});

test('per-service rotation keeps the previous key verifiable once, then retires it', async () => {
    const k1 = rsa();
    const kid1 = (await (await register('orders', k1.publicKey, SECRETS.orders)).json()).kid;
    const k2 = rsa();
    const kid2 = (await (await register('orders', k2.publicKey, SECRETS.orders)).json()).kid;
    const published = async () => (await (await fetch(`${app.baseUrl}/.well-known/services-jwks.json`)).json()).keys.filter((k) => k.service === 'orders');

    let keys = await published();
    assert.deepEqual(keys.map((k) => [k.kid, k.status]).sort(), [[kid1, 'ROTATING'], [kid2, 'ACTIVE']].sort());

    const k3 = rsa();
    await register('orders', k3.publicKey, SECRETS.orders);
    keys = await published();
    assert.ok(!keys.some((k) => k.kid === kid1), 'the oldest key is retired on the next rotation');
    assert.equal(keys.find((k) => k.kid === kid2).status, 'ROTATING');
});

test('revokeServiceKey: a revoked key no longer verifies or publishes; the name can be registered anew', async () => {
    const k = rsa();
    const kid = (await (await register('audit', k.publicKey, SHARED)).json()).kid;
    const token = mint(k.privateKey, kid, { iss: 'audit' });
    assert.equal(await revokeServiceKey(kid), true);

    const keys = (await (await fetch(`${app.baseUrl}/.well-known/services-jwks.json`)).json()).keys;
    assert.ok(!keys.some((x) => x.kid === kid));
    // (the probe allows only billing, but authentication fails first — 401, not 403)
    assert.equal((await ping({ Authorization: `Bearer ${token}` })).status, 401);
    assert.equal((await register('audit', rsa().publicKey, SHARED)).status, 201);
});

test('allowedServiceNames limits who can register at all', async () => {
    app.state.config.serviceMesh.allowedServiceNames = ['billing', 'orders'];
    try {
        assert.equal((await register('newcomer', rsa().publicKey, SHARED)).status, 403);
    } finally {
        delete app.state.config.serviceMesh.allowedServiceNames;
    }
});

test('tokenMode defaults to "token": the shared secret and x-service-name are ignored', async () => {
    assert.equal(app.state.config.serviceMesh.tokenMode, 'token');
    const res = await ping({ 'x-internal-service-secret': 'legacy-shared-secret', 'x-service-name': 'billing' });
    assert.equal(res.status, 401);
});

test('tokenMode "both": a shared-secret caller is refused by requireServiceCallerMiddleware unless explicitly allowed', async () => {
    const mesh = app.state.config.serviceMesh;
    mesh.tokenMode = 'both';
    try {
        const legacy = await ping({ 'x-internal-service-secret': 'legacy-shared-secret', 'x-service-name': 'billing' });
        assert.equal(legacy.status, 403, 'a self-declared name proves nothing');

        mesh.allowLegacySecretCallers = true;
        assert.equal((await ping({ 'x-internal-service-secret': 'legacy-shared-secret', 'x-service-name': 'billing' })).status, 200);
        assert.equal((await ping({ 'x-internal-service-secret': 'wrong', 'x-service-name': 'billing' })).status, 401);
    } finally {
        mesh.tokenMode = 'token';
        delete mesh.allowLegacySecretCallers;
    }
});

test('a missing ownServiceName is a configuration error, never a fallback to the shared secret', async () => {
    const mesh = app.state.config.serviceMesh;
    const saved = mesh.ownServiceName;
    mesh.ownServiceName = undefined;
    mesh.tokenMode = 'both';
    try {
        const res = await ping({ Authorization: `Bearer ${mint(billing.privateKey, billing.kid)}`, 'x-internal-service-secret': 'legacy-shared-secret', 'x-service-name': 'billing' });
        assert.equal(res.status, 500);
        assert.equal((await res.json()).error, 'SERVICE_NOT_CONFIGURED');
    } finally {
        mesh.ownServiceName = saved;
        mesh.tokenMode = 'token';
    }
});

test('the services JWKS never publishes a non-RSA key left over from before 0.4.0', async () => {
    const ec = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({ type: 'spki', format: 'pem' });
    await app.state.storage.serviceKeyRepository.upsertByKid({ kid: 'legacy:ec', name: 'legacy', publicKey: b64(ec) });
    const keys = (await (await fetch(`${app.baseUrl}/.well-known/services-jwks.json`)).json()).keys;
    assert.ok(!keys.some((k) => k.kid === 'legacy:ec'));
    assert.ok(keys.every((k) => k.kty === 'RSA'));
});

test('bootstrap attempts are rate limited per IP', async () => {
    await withTemporaryApp({ config: { serviceMesh: { bootstrapSecret: SHARED }, rateLimiting: { enabled: true, serviceKeyRegistration: { max: 2, windowSeconds: 60 } } } }, async (temp) => {
        assert.equal((await register('x1', rsa().publicKey, 'guess-1', temp.baseUrl)).status, 401);
        assert.equal((await register('x2', rsa().publicKey, 'guess-2', temp.baseUrl)).status, 401);
        assert.equal((await register('x3', rsa().publicKey, SHARED, temp.baseUrl)).status, 429);
    });
});

/** A stand-in IdP JWKS endpoint that counts fetches. */
async function jwksServer(handler) {
    let hits = 0;
    const server = http.createServer((req, res) => { hits += 1; handler(req, res); });
    await new Promise((r) => server.listen(0, r));
    return { url: `http://127.0.0.1:${server.address().port}`, hits: () => hits, stop: () => new Promise((r) => { server.closeAllConnections?.(); server.close(r); }) };
}

test('remote lookup: a flood of unknown kids triggers at most one forced refetch per 30 s', async () => {
    const pub = crypto.createPublicKey(rsa().publicKey).export({ format: 'jwk' });
    const idp = await jwksServer((_req, res) => res.end(JSON.stringify({ keys: [{ ...pub, kid: 'known', service: 'billing' }] })));
    try {
        const lookup = remoteJwksKeyLookup(idp.url);
        assert.ok(await lookup('known'));
        for (let i = 0; i < 50; i += 1) assert.equal(await lookup(`junk-${i}`, { forceRefresh: true }), null);
        assert.equal(idp.hits(), 2, 'initial fetch + one forced refresh');
    } finally {
        await idp.stop();
    }
});

test('remote lookup: a hung JWKS endpoint times out (503), and stale keys are kept when a refresh fails', async () => {
    const hung = await jwksServer(() => { /* never answers */ });
    try {
        const started = Date.now();
        await assert.rejects(remoteJwksKeyLookup(hung.url, { timeoutMs: 200 })('any'), (err) => err.code === 'SERVICE_UNAVAILABLE');
        assert.ok(Date.now() - started < 3000);
    } finally {
        await hung.stop();
    }

    const pub = crypto.createPublicKey(rsa().publicKey).export({ format: 'jwk' });
    let up = true;
    const flaky = await jwksServer((_req, res) => {
        if (!up) { res.statusCode = 500; return res.end(); }
        res.end(JSON.stringify({ keys: [{ ...pub, kid: 'k1', service: 'billing' }] }));
    });
    try {
        const lookup = remoteJwksKeyLookup(flaky.url);
        assert.ok(await lookup('k1'));
        up = false;
        assert.ok(await lookup('k1', { forceRefresh: true }), 'the last good keys are still served');
    } finally {
        await flaky.stop();
    }
});

test('verifyServiceTokenRemote caches its key lookup per IdP URL', async () => {
    const k = rsa();
    const pub = crypto.createPublicKey(k.publicKey).export({ format: 'jwk' });
    const idp = await jwksServer((_req, res) => res.end(JSON.stringify({ keys: [{ ...pub, kid: 'billing:remote', service: 'billing' }] })));
    try {
        for (let i = 0; i < 5; i += 1) {
            const payload = await verifyServiceTokenRemote(mint(k.privateKey, 'billing:remote'), { expectedAud: 'idp', idpBaseUrl: idp.url });
            assert.equal(payload.iss, 'billing');
        }
        assert.equal(idp.hits(), 1);
    } finally {
        await idp.stop();
    }
});
