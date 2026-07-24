import { test } from 'node:test';
import assert from 'node:assert/strict';
import { MemoryRateLimiter } from '../src/rate-limit/memory.adapter.js';
import { NoopRateLimiter } from '../src/rate-limit/noop.adapter.js';

test('MemoryRateLimiter allows up to max, then blocks within the window', async () => {
    const limiter = new MemoryRateLimiter();
    try {
        const opts = { max: 3, windowSeconds: 60 };
        for (let i = 1; i <= 3; i++) {
            const result = await limiter.increment('k1', opts);
            assert.equal(result.allowed, true, `attempt ${i} should be allowed`);
            assert.equal(result.remaining, 3 - i);
        }
        const fourth = await limiter.increment('k1', opts);
        assert.equal(fourth.allowed, false);
        assert.equal(fourth.remaining, 0);
    } finally {
        limiter.close();
    }
});

test('MemoryRateLimiter resets the window after it expires', async () => {
    const limiter = new MemoryRateLimiter();
    try {
        const opts = { max: 1, windowSeconds: 1 };
        const first = await limiter.increment('k2', opts);
        assert.equal(first.allowed, true);
        const second = await limiter.increment('k2', opts);
        assert.equal(second.allowed, false);

        await new Promise((resolve) => setTimeout(resolve, 1100));

        const afterWindow = await limiter.increment('k2', opts);
        assert.equal(afterWindow.allowed, true, 'a new window should start once the old one expires');
    } finally {
        limiter.close();
    }
});

test('MemoryRateLimiter.reset clears a key immediately', async () => {
    const limiter = new MemoryRateLimiter();
    try {
        const opts = { max: 1, windowSeconds: 60 };
        await limiter.increment('k3', opts);
        const blocked = await limiter.increment('k3', opts);
        assert.equal(blocked.allowed, false);

        await limiter.reset('k3');

        const afterReset = await limiter.increment('k3', opts);
        assert.equal(afterReset.allowed, true);
    } finally {
        limiter.close();
    }
});

test('MemoryRateLimiter tracks keys independently', async () => {
    const limiter = new MemoryRateLimiter();
    try {
        const opts = { max: 1, windowSeconds: 60 };
        assert.equal((await limiter.increment('a', opts)).allowed, true);
        assert.equal((await limiter.increment('b', opts)).allowed, true, 'a different key must not share the counter');
        assert.equal((await limiter.increment('a', opts)).allowed, false);
    } finally {
        limiter.close();
    }
});

test('NoopRateLimiter always allows', async () => {
    const limiter = new NoopRateLimiter();
    for (let i = 0; i < 5; i++) {
        assert.equal((await limiter.increment('x', { max: 1, windowSeconds: 60 })).allowed, true);
    }
});
