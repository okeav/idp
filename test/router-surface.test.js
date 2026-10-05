import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { buildTestApp, uniqueEmail } from './helpers/build-test-app.js';
import { serve, json } from './helpers/serve.js';
import { buildRouter } from '../src/routes/build-router.js';

// Issue: buildRouter() used to mount /oauth2/clients* (register, list, get,
// update, approve, rotate-secret, deactivate) with no authentication at all.

let app;

before(async () => {
    app = await buildTestApp();
});

after(async () => {
    await app.stop();
});

const CLIENT_ROUTES = [
    ['POST', '/oauth2/clients'],
    ['GET', '/oauth2/clients'],
    ['GET', '/oauth2/clients/some-client-id'],
    ['PATCH', '/oauth2/clients/some-client-id'],
    ['DELETE', '/oauth2/clients/some-client-id'],
    ['POST', '/oauth2/clients/some-client-id/approve'],
    ['POST', '/oauth2/clients/some-client-id/rotate-secret'],
];
const ALL_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'];

test('without opts.clientManagement, every /oauth2/clients route is 404 for every method', async () => {
    const server = await serve(); // buildRouter() with no options
    try {
        const paths = [...new Set(CLIENT_ROUTES.map(([, p]) => p))];
        for (const path of paths) {
            for (const method of ALL_METHODS) {
                const res = await fetch(`${server.baseUrl}${path}`, {
                    method,
                    headers: { 'Content-Type': 'application/json' },
                    ...(method === 'GET' ? {} : { body: JSON.stringify({ name: 'Evil', slug: `evil-${Date.now()}`, redirectUris: ['https://evil.example/cb'] }) }),
                });
                assert.equal(res.status, 404, `${method} ${path} must not be reachable`);
            }
        }
        // And nothing was created by the attempted registrations.
        const created = await app.state.storage.oauthClientRepository.listMany({ skip: 0, limit: 100 });
        assert.equal(created.filter((c) => c.name === 'Evil').length, 0);
    } finally {
        await server.stop();
    }
});

test('with opts.clientManagement, the middleware runs before every client route and can refuse', async () => {
    const seen = [];
    const refuseAll = (req, res) => {
        seen.push(`${req.method} ${req.originalUrl}`);
        res.status(401).json({ error: 'ADMIN_REQUIRED' });
    };
    const server = await serve({ routerOpts: { clientManagement: { middleware: [refuseAll] } } });
    try {
        for (const [method, path] of CLIENT_ROUTES) {
            const res = await fetch(`${server.baseUrl}${path}`, {
                method,
                headers: { 'Content-Type': 'application/json' },
                ...(method === 'GET' ? {} : { body: JSON.stringify({ name: 'Refused', slug: `refused-${Date.now()}`, redirectUris: ['https://x.example/cb'] }) }),
            });
            assert.equal(res.status, 401, `${method} ${path} must hit the admin middleware`);
            assert.equal((await res.json()).error, 'ADMIN_REQUIRED');
        }
        assert.equal(seen.length, CLIENT_ROUTES.length);
        const created = await app.state.storage.oauthClientRepository.listMany({ skip: 0, limit: 100 });
        assert.equal(created.filter((c) => c.name === 'Refused').length, 0, 'the handler must never run when the middleware refuses');
    } finally {
        await server.stop();
    }
});

test('with opts.clientManagement, all middleware run in order and an allowed request reaches the handler', async () => {
    const order = [];
    const first = (_req, _res, next) => { order.push('first'); next(); };
    const second = (req, res, next) => {
        order.push('second');
        if (req.headers['x-admin'] !== 'yes') return res.status(403).json({ error: 'FORBIDDEN' });
        next();
    };
    const server = await serve({ routerOpts: { clientManagement: { middleware: [first, second] } } });
    try {
        const denied = await fetch(`${server.baseUrl}/oauth2/clients`, json({ name: 'X', slug: `x-${Date.now()}`, redirectUris: ['https://x.example/cb'] }));
        assert.equal(denied.status, 403);
        assert.deepEqual(order, ['first', 'second']);

        const allowed = await fetch(`${server.baseUrl}/oauth2/clients`, json({ name: 'Allowed', slug: `allowed-${Date.now()}`, redirectUris: ['https://x.example/cb'] }, { 'x-admin': 'yes' }));
        assert.equal(allowed.status, 201, await allowed.text());
    } finally {
        await server.stop();
    }
});

test('misconfigured clientManagement throws at buildRouter() time instead of mounting the routes open', () => {
    for (const bad of [{}, { middleware: [] }, { middleware: null }, { middleware: 'requireAdmin' }, { middleware: [() => {}, 'nope'] }, true]) {
        assert.throws(() => buildRouter({ clientManagement: bad }), /clientManagement/, `should reject ${JSON.stringify(bad)}`);
    }
    // A single function is accepted as shorthand for a one-element list.
    assert.doesNotThrow(() => buildRouter({ clientManagement: { middleware: (_req, _res, next) => next() } }));
});

test('opts.features switches surfaces off; unknown feature names throw', async () => {
    assert.throws(() => buildRouter({ features: { oauth: false } }), /unknown opts\.features/);

    const server = await serve({ routerOpts: { features: { magicLink: false, webauthn: false, sso: false, oauth2: false, oidc: false, serviceMesh: false } } });
    try {
        const off = [
            ['POST', '/magic-link/request'], ['POST', '/webauthn/authentication/options'], ['GET', '/sso/google'],
            ['POST', '/oauth2/token'], ['GET', '/oauth2/authorize'], ['GET', '/userinfo'],
            ['GET', '/.well-known/openid-configuration'], ['GET', '/.well-known/services-jwks.json'], ['POST', '/internal/service-keys'],
        ];
        for (const [method, path] of off) {
            const res = await fetch(`${server.baseUrl}${path}`, { method, headers: { 'Content-Type': 'application/json' }, ...(method === 'GET' ? {} : { body: '{}' }) });
            assert.equal(res.status, 404, `${method} ${path} should be unmounted`);
        }
        // Core password auth and JWKS stay mounted.
        assert.equal((await fetch(`${server.baseUrl}/.well-known/jwks.json`)).status, 200);
        assert.notEqual((await fetch(`${server.baseUrl}/login`, json({ email: 'a@b.co', password: 'x' }))).status, 404);
    } finally {
        await server.stop();
    }
});

test('POST /logout accepts the refresh token from the httpOnly cookie alone (no body)', async () => {
    const email = uniqueEmail('logout-cookie');
    const password = 'Str0ng!Passw0rd';
    await fetch(`${app.baseUrl}/register`, json({ email, password }));
    const code = app.hookCalls.onVerificationEmailRequested.find((c) => c.email === email).verificationCode;
    await fetch(`${app.baseUrl}/register/verify-email`, json({ email, code }));
    const { refreshToken } = await (await fetch(`${app.baseUrl}/login`, json({ email, password }))).json();

    const res = await fetch(`${app.baseUrl}/logout`, { method: 'POST', headers: { Cookie: `refresh_token=${refreshToken}` } });
    assert.equal(res.status, 200, await res.text());

    const reuse = await fetch(`${app.baseUrl}/refresh`, json({ refreshToken }));
    assert.equal(reuse.status, 401, 'the cookie-identified session must actually be revoked');

    // An empty JSON body with the cookie works too, and a body token still works.
    const { refreshToken: second } = await (await fetch(`${app.baseUrl}/login`, json({ email, password }))).json();
    assert.equal((await fetch(`${app.baseUrl}/logout`, { method: 'POST', headers: { 'Content-Type': 'application/json', Cookie: `refresh_token=${second}` }, body: '{}' })).status, 200);
    const { refreshToken: third } = await (await fetch(`${app.baseUrl}/login`, json({ email, password }))).json();
    assert.equal((await fetch(`${app.baseUrl}/logout`, json({ refreshToken: third }))).status, 200);

    // Neither cookie nor body is still a 400, and unknown fields are still rejected.
    assert.equal((await fetch(`${app.baseUrl}/logout`, { method: 'POST' })).status, 400);
    assert.equal((await fetch(`${app.baseUrl}/logout`, json({ refreshToken: third, extra: 1 }))).status, 400);
});
