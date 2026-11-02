import crypto from 'crypto';
import { IdpError } from '../errors/idp-error.js';

const CACHE_TTL_MS = 5 * 60 * 1000;
// A forced refresh (unknown kid) happens at most this often: otherwise every request carrying a junk
// kid — no credentials needed — makes this service fetch the IdP's JWKS.
const MIN_FORCED_REFRESH_INTERVAL_MS = 30 * 1000;
const FETCH_TIMEOUT_MS = 5000;
// After a failed fetch, wait this long before trying again (the IdP may be down — don't hammer it).
const FAILURE_BACKOFF_MS = 30 * 1000;

/**
 * HTTP-based key lookup for a downstream service that verifies inbound S2S
 * calls from peers but doesn't run the IDP itself (no direct DB access).
 * Fetches `${idpBaseUrl}/.well-known/services-jwks.json` with a short
 * in-memory cache, force-refreshing on a kid miss (peer rotated) — rate
 * limited, with a timeout, and keeping the last good keys if a refresh fails.
 */
export function remoteJwksKeyLookup(idpBaseUrl, { timeoutMs = FETCH_TIMEOUT_MS } = {}) {
    const jwksUrl = `${idpBaseUrl.replace(/\/$/, '')}/.well-known/services-jwks.json`;
    let cache = new Map();
    let fetchedAt = 0;
    let lastForcedAt = 0;
    let retryAfter = 0;
    let inflight = null;

    async function refresh() {
        if (inflight) return inflight;
        inflight = (async () => {
            const res = await fetch(jwksUrl, { redirect: 'error', signal: AbortSignal.timeout(timeoutMs) });
            if (!res.ok) throw new Error(`JWKS fetch failed: ${res.status}`);
            const body = await res.json();
            const fresh = new Map();
            for (const jwk of body.keys ?? []) {
                if (!jwk.kid || jwk.kty !== 'RSA') continue;
                try {
                    const pem = crypto.createPublicKey({ key: jwk, format: 'jwk' }).export({ format: 'pem', type: 'spki' }).toString('utf8');
                    fresh.set(jwk.kid, { publicKeyPem: pem, service: jwk.service });
                } catch {
                    // skip an unreadable key rather than failing the whole set
                }
            }
            cache = fresh;
            fetchedAt = Date.now();
        })();
        try {
            await inflight;
        } finally {
            inflight = null;
        }
    }

    return async (kid, { forceRefresh = false } = {}) => {
        const now = Date.now();
        const stale = !fetchedAt || now - fetchedAt > CACHE_TTL_MS;
        const mayForce = forceRefresh && now - lastForcedAt >= MIN_FORCED_REFRESH_INTERVAL_MS;
        if ((stale || mayForce) && now >= retryAfter) {
            if (mayForce) lastForcedAt = now;
            try {
                await refresh();
            } catch (cause) {
                retryAfter = Date.now() + FAILURE_BACKOFF_MS;
                // Keep serving the keys we have; with none at all there is nothing to verify against.
                if (!fetchedAt) throw new IdpError({ code: 'SERVICE_UNAVAILABLE', httpStatus: 503, message: 'Service keys are unavailable', cause });
            }
        } else if (!fetchedAt) {
            throw new IdpError({ code: 'SERVICE_UNAVAILABLE', httpStatus: 503, message: 'Service keys are unavailable' });
        }
        return cache.get(kid) ?? null;
    };
}
