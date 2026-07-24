import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { withTemporaryApp, uniqueEmail } from './helpers/build-test-app.js';
import { verifyWebhookSignature } from '../src/index.js';

/**
 * A tiny local HTTP receiver standing in for a consumer's webhook endpoint.
 * `behavior(attemptNumber)` lets a test script a receiver that fails N times
 * before succeeding, to exercise the dispatcher's retry logic for real over
 * a real socket rather than mocking fetch.
 */
async function startReceiver(behavior = () => 200) {
    const deliveries = [];
    const attemptsByEvent = new Map(); // scoped per event: onAuditLog and named hooks fire independent, concurrent retry loops against the same receiver
    const server = http.createServer((req, res) => {
        const chunks = [];
        req.on('data', (c) => chunks.push(c));
        req.on('end', () => {
            const event = req.headers['x-idp-event'];
            const attempt = (attemptsByEvent.get(event) || 0) + 1;
            attemptsByEvent.set(event, attempt);
            const rawBody = Buffer.concat(chunks).toString('utf8');
            deliveries.push({ rawBody, headers: { ...req.headers } });
            const status = behavior(attempt, event);
            res.writeHead(status).end();
        });
    });
    await new Promise((resolve) => server.listen(0, resolve));
    const { port } = server.address();
    return {
        url: `http://127.0.0.1:${port}/webhook`,
        deliveries,
        async stop() {
            await new Promise((resolve) => server.close(resolve));
        },
    };
}

test('webhooks: a real audit event is delivered with a verifiable HMAC signature', async () => {
    const secret = 'whsec_test_secret_1';
    const receiver = await startReceiver();
    try {
        await withTemporaryApp(
            { config: { webhooks: { endpoints: [{ url: receiver.url, secret }] } } },
            async (app) => {
                const email = uniqueEmail('webhook-basic');
                const res = await fetch(`${app.baseUrl}/register`, {
                    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email, password: 'Str0ng!Passw0rd' }),
                });
                assert.equal(res.status, 201);

                // Delivery happens on a background timer, not blocking the request above.
                await new Promise((resolve) => setTimeout(resolve, 300));
            }
        );

        assert.ok(receiver.deliveries.length >= 1, 'expected at least one webhook delivery');
        const delivery = receiver.deliveries.find((d) => d.headers['x-idp-event'] === 'REGISTERED');
        assert.ok(delivery, 'expected a REGISTERED event delivery');

        const valid = verifyWebhookSignature(secret, delivery.rawBody, delivery.headers['x-idp-signature']);
        assert.equal(valid, true);

        const wrongSecret = verifyWebhookSignature('wrong-secret', delivery.rawBody, delivery.headers['x-idp-signature']);
        assert.equal(wrongSecret, false);

        const parsed = JSON.parse(delivery.rawBody);
        assert.equal(parsed.event, 'REGISTERED');
        assert.ok(parsed.payload.userId);
        assert.ok(delivery.headers['x-idp-delivery']);
    } finally {
        await receiver.stop();
    }
});

test('webhooks: retries with backoff and eventually succeeds against a flaky endpoint', async () => {
    const secret = 'whsec_test_secret_2';
    const receiver = await startReceiver((attempt, event) => (event === 'REGISTERED' && attempt < 3 ? 500 : 200));
    const registeredDeliveries = () => receiver.deliveries.filter((d) => d.headers['x-idp-event'] === 'REGISTERED');
    try {
        await withTemporaryApp(
            { config: { webhooks: { endpoints: [{ url: receiver.url, secret }], maxAttempts: 5, retryBaseDelayMs: 20 } } },
            async (app) => {
                const email = uniqueEmail('webhook-retry');
                await fetch(`${app.baseUrl}/register`, {
                    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email, password: 'Str0ng!Passw0rd' }),
                });

                // Poll rather than a fixed sleep — only 20+40=60ms of backoff is
                // needed before the 3rd (successful) attempt, but a generous,
                // repeatedly-checked ceiling avoids flakiness under CI/system load.
                const deadline = Date.now() + 5000;
                while (registeredDeliveries().length < 3 && Date.now() < deadline) {
                    await new Promise((resolve) => setTimeout(resolve, 50));
                }
            }
        );

        assert.equal(registeredDeliveries().length, 3, 'expected exactly 3 attempts: 2 failures then 1 success');
    } finally {
        await receiver.stop();
    }
});

test('webhooks: an unreachable endpoint never blocks or fails the underlying auth operation', async () => {
    await withTemporaryApp(
        {
            config: {
                webhooks: {
                    endpoints: [{ url: 'http://127.0.0.1:1/unreachable', secret: 'whsec_unreachable' }],
                    maxAttempts: 3,
                    retryBaseDelayMs: 10,
                    timeoutMs: 200,
                },
            },
        },
        async (app) => {
            const email = uniqueEmail('webhook-unreachable');
            const start = Date.now();
            const res = await fetch(`${app.baseUrl}/register`, {
                method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email, password: 'Str0ng!Passw0rd' }),
            });
            const elapsed = Date.now() - start;
            assert.equal(res.status, 201);
            assert.ok(elapsed < 1000, `request should return immediately, not wait on webhook retries (took ${elapsed}ms)`);
        }
    );
});

test('webhooks: disabled by default when no endpoints are configured (no-op, no network calls)', async () => {
    await withTemporaryApp({}, async (app) => {
        assert.equal(app.state.webhookDispatcher.isNoop, true);
        const email = uniqueEmail('webhook-disabled');
        const res = await fetch(`${app.baseUrl}/register`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email, password: 'Str0ng!Passw0rd' }),
        });
        assert.equal(res.status, 201);
    });
});
