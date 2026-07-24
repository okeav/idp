import crypto from 'crypto';
import { buildSignatureHeader } from './sign.js';

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Delivers signed event payloads to consumer-configured HTTP endpoints,
 * additive to the in-process hooks (never a replacement for them). Every
 * public method is fire-and-forget: `dispatch()` never returns a promise the
 * caller is expected to await, and delivery failures — including a
 * permanently unreachable endpoint after all retries — only ever get logged,
 * never thrown back into the auth operation that triggered the event.
 */
export class WebhookDispatcher {
    constructor({ endpoints = [], maxAttempts = 5, retryBaseDelayMs = 500, timeoutMs = 5000 } = {}, logger) {
        this.endpoints = endpoints.filter((e) => e?.url && e?.secret);
        this.maxAttempts = maxAttempts;
        this.retryBaseDelayMs = retryBaseDelayMs;
        this.timeoutMs = timeoutMs;
        this.logger = logger;
    }

    get isNoop() {
        return this.endpoints.length === 0;
    }

    /** Fire-and-forget. Never throws, never returns a promise callers need to await. */
    dispatch(event, payload) {
        if (this.isNoop) return;
        const rawBody = JSON.stringify({ event, payload, timestamp: new Date().toISOString() });
        for (const endpoint of this.endpoints) {
            this._deliverWithRetry(endpoint, event, rawBody).catch((err) => {
                this.logger?.warn?.({ err, event, url: endpoint.url }, 'Webhook delivery failed after all retries — ignoring');
            });
        }
    }

    async _deliverWithRetry(endpoint, event, rawBody) {
        const deliveryId = crypto.randomUUID();
        for (let attempt = 1; attempt <= this.maxAttempts; attempt += 1) {
            try {
                await this._send(endpoint, rawBody, event, deliveryId);
                return;
            } catch (err) {
                if (attempt >= this.maxAttempts) throw err;
                await sleep(this.retryBaseDelayMs * 2 ** (attempt - 1));
            }
        }
    }

    async _send(endpoint, rawBody, event, deliveryId) {
        const timestamp = Math.floor(Date.now() / 1000);
        const signature = buildSignatureHeader(endpoint.secret, timestamp, rawBody);

        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), this.timeoutMs);
        try {
            const res = await fetch(endpoint.url, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Idp-Event': event,
                    'X-Idp-Delivery': deliveryId,
                    'X-Idp-Signature': signature,
                },
                body: rawBody,
                signal: controller.signal,
            });
            if (!res.ok) throw new Error(`webhook endpoint ${endpoint.url} responded with status ${res.status}`);
        } finally {
            clearTimeout(timeout);
        }
    }
}
