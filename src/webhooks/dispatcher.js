import crypto from 'crypto';
import { buildSignatureHeader } from './sign.js';

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);
const MIN_SECRET_LENGTH = 16;

/** A URL safe to put in a log line: no credentials, no query string. */
function redactUrl(url) {
    try {
        const u = new URL(url);
        return `${u.origin}${u.pathname}`;
    } catch {
        return '<invalid url>';
    }
}

/**
 * Validates one configured endpoint (at startup): https only (http only to a loopback host), a
 * signing secret of at least 16 characters, and an optional `events` allowlist.
 */
function validateEndpoint(endpoint, i) {
    const where = `config.webhooks.endpoints[${i}]`;
    let url;
    try {
        url = new URL(endpoint?.url);
    } catch {
        throw new Error(`${where}.url is not a valid URL`);
    }
    if (url.protocol !== 'https:' && !(url.protocol === 'http:' && LOOPBACK_HOSTS.has(url.hostname))) {
        throw new Error(`${where}.url must be https (http only for localhost) — deliveries carry account data`);
    }
    if (typeof endpoint.secret !== 'string' || endpoint.secret.length < MIN_SECRET_LENGTH) {
        throw new Error(`${where}.secret must be a string of at least ${MIN_SECRET_LENGTH} characters`);
    }
    if (endpoint.events !== undefined && !(Array.isArray(endpoint.events) && endpoint.events.every((e) => typeof e === 'string'))) {
        throw new Error(`${where}.events must be an array of event names`);
    }
    return { url: endpoint.url, secret: endpoint.secret, events: endpoint.events ? new Set(endpoint.events) : null, includeCredentials: endpoint.includeCredentials === true };
}

/**
 * Delivers signed event payloads to consumer-configured HTTP endpoints,
 * additive to the in-process hooks (never a replacement for them). Every
 * public method is fire-and-forget: `dispatch()` never returns a promise the
 * caller is expected to await, and delivery failures — including a
 * permanently unreachable endpoint after all retries — only ever get logged,
 * never thrown back into the auth operation that triggered the event.
 *
 * Per endpoint: `events` limits which events it receives; credential fields (reset tokens,
 * magic-link tokens, verification codes) are stripped unless `includeCredentials: true` — a
 * receiver that only analyses events must never be able to take over accounts. At most
 * `maxInFlight` deliveries (including their retries) run at once; beyond that, events are dropped
 * with a warning rather than queued without bound. Redirects are not followed.
 */
export class WebhookDispatcher {
    constructor({ endpoints = [], maxAttempts = 5, retryBaseDelayMs = 500, timeoutMs = 5000, maxInFlight = 100 } = {}, logger) {
        this.endpoints = endpoints.map(validateEndpoint);
        this.maxAttempts = maxAttempts;
        this.retryBaseDelayMs = retryBaseDelayMs;
        this.timeoutMs = timeoutMs;
        this.maxInFlight = maxInFlight;
        this.inFlight = 0;
        this.logger = logger;
    }

    get isNoop() {
        return this.endpoints.length === 0;
    }

    /**
     * Fire-and-forget. Never throws, never returns a promise callers need to await.
     * @param {{ credentialFields?: string[] }} [opts] - payload fields that are credentials.
     */
    dispatch(event, payload, { credentialFields = [] } = {}) {
        if (this.isNoop) return;
        for (const endpoint of this.endpoints) {
            if (endpoint.events && !endpoint.events.has(event)) continue;
            if (this.inFlight >= this.maxInFlight) {
                this.logger?.warn?.({ event, url: redactUrl(endpoint.url), maxInFlight: this.maxInFlight }, 'Webhook backlog full — event dropped');
                continue;
            }

            let body = payload;
            if (credentialFields.length > 0 && !endpoint.includeCredentials && payload && typeof payload === 'object') {
                body = { ...payload };
                for (const field of credentialFields) delete body[field];
            }
            // The delivery id is part of the signed body, so a receiver can de-duplicate on it and a
            // replayed delivery can't be passed off as a new one by changing a header.
            const id = crypto.randomUUID();
            const rawBody = JSON.stringify({ id, event, payload: body, timestamp: new Date().toISOString() });

            this.inFlight += 1;
            this._deliverWithRetry(endpoint, event, id, rawBody)
                .catch((err) => {
                    this.logger?.warn?.({ err: err?.message, event, url: redactUrl(endpoint.url) }, 'Webhook delivery failed after all retries — ignoring');
                })
                .finally(() => {
                    this.inFlight -= 1;
                });
        }
    }

    async _deliverWithRetry(endpoint, event, deliveryId, rawBody) {
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

        const res = await fetch(endpoint.url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Idp-Event': event,
                'X-Idp-Delivery': deliveryId,
                'X-Idp-Signature': signature,
            },
            body: rawBody,
            redirect: 'manual', // a 3xx is a failure — never re-send a signed body to wherever it points
            signal: AbortSignal.timeout(this.timeoutMs),
        });
        if (!res.ok) throw new Error(`webhook endpoint ${redactUrl(endpoint.url)} responded with status ${res.status}`);
    }
}
