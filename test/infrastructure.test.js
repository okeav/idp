import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import mongoose from 'mongoose';
import { withTemporaryApp, uniqueEmail, TEST_SECURITY } from './helpers/build-test-app.js';
import { json } from './helpers/serve.js';
import { configFromEnv, initIdentityProvider, MemoryCacheAdapter, MemoryRateLimiter, RedisRateLimiter, createRedisRateLimiter } from '../src/index.js';
import { ipKey } from '../src/rate-limit/keys.js';
import { defineIdentityUserModel } from '../src/storage/mongo/models/identity-user.model.js';

// Infrastructure issues found in the 0.3.0 audit: lenient env parsing that
// silently disabled protections, weak secrets/keys accepted at startup,
// unbounded in-memory stores, IPv6 rate-limit keys per address, plaintext
// emails in limiter keys, an unindexed email lookup, and Redis gaps.

const rsa = (bits = 2048) => crypto.generateKeyPairSync('rsa', { modulusLength: bits, publicKeyEncoding: { type: 'spki', format: 'pem' }, privateKeyEncoding: { type: 'pkcs8', format: 'pem' } });
const KEY = rsa();

/** A config that passes every startup check; `initIdentityProvider` fails before connecting to Mongo if one doesn't. */
const baseConfig = (patch = {}) => ({
    issuer: 'https://idp.test.local',
    mongo: { uri: 'mongodb://127.0.0.1:1/never-connected' },
    signingKeys: { keys: { k1: { privateKey: KEY.privateKey, publicKey: KEY.publicKey, status: 'ACTIVE' } } },
    security: { ...TEST_SECURITY },
    mfa: { enabled: false },
    logger: { info() {}, warn() {}, error() {}, debug() {} },
    ...patch,
});

test('configFromEnv: booleans and numbers are parsed strictly — never silently off', () => {
    const env = (vars) => configFromEnv({ NODE_ENV: 'production', ...vars });
    assert.equal(env({ IDP_COOKIE_SECURE: '' }).cookies.secure, true, 'blank means default (secure in production)');
    for (const v of ['1', 'TRUE', 'yes', ' on ']) assert.equal(env({ IDP_RATE_LIMIT_ENABLED: v }).rateLimiting.enabled, true, v);
    for (const v of ['0', 'False', 'no', 'off']) assert.equal(env({ IDP_RATE_LIMIT_ENABLED: v }).rateLimiting.enabled, false, v);
    assert.throws(() => env({ IDP_SESSION_VERIFY_ON_EACH_REQUEST: 'maybe' }), /IDP_SESSION_VERIFY_ON_EACH_REQUEST/);
    assert.throws(() => env({ IDP_MAX_FAILED_LOGIN_ATTEMPTS: 'five' }), /IDP_MAX_FAILED_LOGIN_ATTEMPTS/);
    assert.throws(() => env({ IDP_BCRYPT_ROUNDS: '4' }), /IDP_BCRYPT_ROUNDS/);
    assert.equal(env({ IDP_MAX_FAILED_LOGIN_ATTEMPTS: '7' }).security.maxFailedLoginAttempts, 7);
});

test('configFromEnv: SSO and service-mesh settings', () => {
    const c = configFromEnv({
        IDP_SSO_BASE_CALLBACK_URL: 'https://idp.example.com',
        IDP_SSO_ALLOWED_REDIRECT_ORIGINS: 'https://app.example.com, https://admin.example.com',
        IDP_S2S_BOOTSTRAP_SECRETS: 'billing=secret-1,orders=secret=with=equals',
        IDP_S2S_OWN_SERVICE_NAME: 'idp',
    });
    assert.deepEqual(c.sso, { baseCallbackUrl: 'https://idp.example.com', allowedRedirectOrigins: ['https://app.example.com', 'https://admin.example.com'] });
    assert.deepEqual(c.serviceMesh.bootstrapSecrets, { billing: 'secret-1', orders: 'secret=with=equals' });
    assert.equal(c.serviceMesh.tokenMode, 'token');
    assert.equal(c.serviceMesh.ownServiceName, 'idp');
    assert.throws(() => configFromEnv({ IDP_S2S_BOOTSTRAP_SECRETS: 'no-separator' }), /name=secret/);
});

test('startup refuses weak secrets, a weak password-hash cost, and non-numeric limits', async () => {
    const cases = [
        [{ security: { ...TEST_SECURITY, emailHashPepper: 'short' } }, /emailHashPepper/],
        [{ security: { ...TEST_SECURITY, tokenHashSecret: 'x'.repeat(31) } }, /tokenHashSecret/],
        [{ security: { ...TEST_SECURITY, allowWeakBcryptRounds: false } }, /bcryptRounds/],
        [{ security: { ...TEST_SECURITY, maxFailedLoginAttempts: NaN } }, /maxFailedLoginAttempts/],
        [{ rateLimiting: { login: { max: 5, windowSeconds: 0.5 } } }, /rateLimiting\.login/],
    ];
    for (const [patch, message] of cases) {
        await assert.rejects(initIdentityProvider(baseConfig(patch)), message);
    }
});

test('startup refuses unusable signing keys: non-RSA, under 2048 bits, mismatched pair, or nothing to sign with', async () => {
    const other = rsa();
    const ec = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256', publicKeyEncoding: { type: 'spki', format: 'pem' }, privateKeyEncoding: { type: 'pkcs8', format: 'pem' } });
    const weak = rsa(1024);
    const keys = (entry) => ({ signingKeys: { keys: { k1: { status: 'ACTIVE', ...entry } } } });
    const cases = [
        [keys({ privateKey: ec.privateKey, publicKey: ec.publicKey }), /RSA/],
        [keys({ privateKey: weak.privateKey, publicKey: weak.publicKey }), /2048/],
        [keys({ privateKey: KEY.privateKey, publicKey: other.publicKey }), /not a pair/],
        [keys({ publicKey: KEY.publicKey }), /privateKey to sign/],
        [keys({ privateKey: KEY.privateKey, publicKey: 'garbage' }), /not a valid public key/],
        [keys({ privateKey: KEY.privateKey, publicKey: KEY.publicKey, status: 'SOMETIMES' }), /status/],
    ];
    for (const [patch, message] of cases) {
        await assert.rejects(initIdentityProvider(baseConfig(patch)), message);
    }
});

test('ipKey: IPv4 as-is, IPv4-mapped unwrapped, IPv6 collapsed to its /64', () => {
    assert.equal(ipKey('203.0.113.7'), '203.0.113.7');
    assert.equal(ipKey('::ffff:203.0.113.7'), '203.0.113.7');
    assert.equal(ipKey('2001:db8:aa:bb:1:2:3:4'), '2001:db8:aa:bb::/64');
    assert.equal(ipKey('2001:db8:aa:bb::99'), '2001:db8:aa:bb::/64', 'every address in the /64 shares a bucket');
    assert.equal(ipKey('2001:0DB8:00aa:00bb:ffff::1%eth0'), '2001:db8:aa:bb::/64');
    assert.equal(ipKey('::1'), '0:0:0:0::/64');
    assert.equal(ipKey(undefined), 'unknown');
});

test('rate-limit keys never contain the email address', async () => {
    await withTemporaryApp({}, async (temp) => {
        const keys = [];
        const saved = temp.state.rateLimiter;
        temp.state.rateLimiter = { increment: async (key) => { keys.push(key); return { allowed: true }; }, check: async () => ({}), reset: async () => {} };
        try {
            const email = uniqueEmail('limiter-key');
            await fetch(`${temp.baseUrl}/login`, json({ email, password: 'Wr0ng!Passw0rd' }));
            await fetch(`${temp.baseUrl}/password/forgot`, json({ email }));
            await fetch(`${temp.baseUrl}/register`, json({ email, password: 'Str0ng!Passw0rd' }));
        } finally {
            temp.state.rateLimiter = saved;
        }
        const perEmail = keys.filter((k) => /^(login:email|password-reset:email|verification-email):/.test(k));
        assert.equal(perEmail.length, 3, keys.join(' | '));
        for (const k of keys) assert.ok(!k.includes('@'), k);
        for (const k of perEmail) assert.match(k, /:[0-9a-f]{64}$/);
    });
});

test('MemoryCacheAdapter is bounded: when full, expired entries go first, then the oldest', async () => {
    const cache = new MemoryCacheAdapter({ maxEntries: 3 });
    try {
        await cache.set('expired', 1, -1);
        await cache.set('a', 1, 60);
        await cache.set('b', 2, 60);
        await cache.set('c', 3, 60); // full: the expired entry makes room
        assert.equal(await cache.get('a'), 1);
        await cache.set('d', 4, 60); // full: the oldest live entry ("a") goes
        assert.equal(await cache.get('a'), null);
        assert.deepEqual([await cache.get('b'), await cache.get('c'), await cache.get('d')], [2, 3, 4]);
    } finally {
        cache.close();
    }
});

test('MemoryRateLimiter is bounded: when full it refuses NEW keys (fail-closed) instead of evicting counters', async () => {
    const limiter = new MemoryRateLimiter({ maxKeys: 2 });
    try {
        const rule = { max: 3, windowSeconds: 60 };
        await limiter.increment('victim-ip', rule);
        await limiter.increment('a', rule);
        await assert.rejects(limiter.increment('flood-1', rule), /full/);
        // Existing counters keep counting — flooding new keys can't reset anyone's limit.
        await limiter.increment('victim-ip', rule);
        await limiter.increment('victim-ip', rule);
        assert.equal((await limiter.increment('victim-ip', rule)).allowed, false);
    } finally {
        limiter.close();
    }
});

test('Redis rate limiter: the window is a whole number of seconds; no host means no silent localhost connection', async () => {
    const calls = [];
    const fake = { eval: async (...args) => { calls.push(args); return [1, 1]; } };
    await new RedisRateLimiter({ redis: fake }).increment('k', { max: 5, windowSeconds: 0.5 });
    assert.equal(calls[0][3], 1, 'a fractional window is rounded up — EXPIRE rejects non-integers');
    assert.match(calls[0][0], /TTL', KEYS\[1\]\) == -1/, 'the expiry is set whenever the key has none');
    await assert.rejects(createRedisRateLimiter({}), /refusing to connect to an unconfigured localhost/);
});

test('the user email field is indexed (the legacy branch of findByEmail\'s $or)', () => {
    const conn = mongoose.createConnection();
    try {
        const model = defineIdentityUserModel(conn, { hashEmail: (e) => e });
        assert.ok(model.schema.indexes().some(([fields]) => fields.email === 1 && Object.keys(fields).length === 1));
    } finally {
        conn.close();
    }
});
