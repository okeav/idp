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
 * `X-Idp-Signature` header (`t=<unix seconds>,v1=<hex hmac>`) against the raw
 * request body, rejecting stale deliveries via `toleranceSeconds`.
 *
 * @param {string} secret - the shared secret configured for this endpoint
 * @param {string} rawBody - the exact, unparsed request body bytes/string
 * @param {string} signatureHeader - the `X-Idp-Signature` header value
 * @param {{ toleranceSeconds?: number }} [opts]
 * @returns {boolean}
 */
export function verifyWebhookSignature(secret, rawBody, signatureHeader, opts = {}) {
    const toleranceSeconds = opts.toleranceSeconds ?? 5 * 60;
    if (typeof signatureHeader !== 'string') return false;

    const parts = Object.fromEntries(
        signatureHeader.split(',').map((part) => {
            const [key, value] = part.split('=');
            return [key, value];
        })
    );
    const timestamp = Number(parts.t);
    const providedSignature = parts.v1;
    if (!timestamp || !providedSignature) return false;

    if (Math.abs(Date.now() / 1000 - timestamp) > toleranceSeconds) return false;

    const expectedSignature = signWebhookPayload(secret, timestamp, rawBody);
    const expected = Buffer.from(expectedSignature, 'hex');
    const provided = Buffer.from(providedSignature, 'hex');
    if (expected.length !== provided.length) return false;
    return crypto.timingSafeEqual(expected, provided);
}
