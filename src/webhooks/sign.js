import crypto from 'crypto';

/**
 * Stripe-style webhook signing: sign `${timestamp}.${rawBody}` with
 * HMAC-SHA256 so a receiving consumer can verify both authenticity and that
 * the delivery isn't a stale replay, without ever needing to parse the body
 * before verifying it.
 */
export function signWebhookPayload(secret, timestamp, rawBody) {
    return crypto.createHmac('sha256', secret).update(`${timestamp}.${rawBody}`).digest('hex');
}

export function buildSignatureHeader(secret, timestamp, rawBody) {
    return `t=${timestamp},v1=${signWebhookPayload(secret, timestamp, rawBody)}`;
}

/**
 * For consumers receiving webhook deliveries from this package. Verifies the
 * `X-Idp-Signature` header (`t=<unix seconds>,v1=<hex hmac>[,v1=…]`) against the raw
 * request body, rejecting stale deliveries via `toleranceSeconds`.
 *
 * Rotation: pass an array of secrets (current and previous) to accept either, and the header may
 * carry several `v1` signatures — any one matching suffices. After verifying, de-duplicate on the
 * body's `id` (signed, unlike the `X-Idp-Delivery` header) to reject a replay within the tolerance.
 *
 * @param {string | string[]} secret - the shared secret(s) configured for this endpoint
 * @param {string} rawBody - the exact, unparsed request body bytes/string
 * @param {string} signatureHeader - the `X-Idp-Signature` header value
 * @param {{ toleranceSeconds?: number }} [opts]
 * @returns {boolean}
 */
export function verifyWebhookSignature(secret, rawBody, signatureHeader, opts = {}) {
    const toleranceSeconds = opts.toleranceSeconds ?? 5 * 60;
    if (typeof signatureHeader !== 'string' || typeof rawBody !== 'string') return false;
    const secrets = (Array.isArray(secret) ? secret : [secret]).filter((s) => typeof s === 'string' && s.length > 0);
    if (secrets.length === 0) return false;

    let timestamp = NaN;
    const provided = [];
    for (const part of signatureHeader.split(',')) {
        const idx = part.indexOf('=');
        if (idx < 0) continue;
        const key = part.slice(0, idx).trim();
        const value = part.slice(idx + 1).trim();
        if (key === 't') timestamp = Number(value);
        else if (key === 'v1' && /^[0-9a-f]{64}$/i.test(value)) provided.push(Buffer.from(value, 'hex'));
    }
    if (!Number.isFinite(timestamp) || timestamp <= 0 || provided.length === 0) return false;
    if (Math.abs(Date.now() / 1000 - timestamp) > toleranceSeconds) return false;

    return secrets.some((s) => {
        const expected = Buffer.from(signWebhookPayload(s, timestamp, rawBody), 'hex');
        return provided.some((p) => p.length === expected.length && crypto.timingSafeEqual(p, expected));
    });
}
