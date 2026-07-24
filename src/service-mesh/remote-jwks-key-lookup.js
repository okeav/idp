import crypto from 'crypto';

const CACHE_TTL_MS = 5 * 60 * 1000;

/**
 * HTTP-based key lookup for a downstream service that verifies inbound S2S
 * calls from peers but doesn't run the IDP itself (no direct DB access).
 * Fetches `${idpBaseUrl}/.well-known/services-jwks.json` with a short
 * in-memory cache, force-refreshing once on a kid miss (peer rotated).
 */
export function remoteJwksKeyLookup(idpBaseUrl) {
    const jwksUrl = `${idpBaseUrl.replace(/\/$/, '')}/.well-known/services-jwks.json`;
    let cache = new Map();
    let fetchedAt = 0;
    let inflight = null;

    async function refresh() {
        if (inflight) return inflight;
        inflight = (async () => {
            const res = await fetch(jwksUrl);
            if (!res.ok) throw new Error(`JWKS fetch failed: ${res.status}`);
            const body = await res.json();
            const fresh = new Map();
            for (const jwk of body.keys ?? []) {
                if (!jwk.kid) continue;
                const pem = crypto.createPublicKey({ key: jwk, format: 'jwk' }).export({ format: 'pem', type: 'spki' }).toString('utf8');
                fresh.set(jwk.kid, { publicKeyPem: pem, service: jwk.service });
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
        if (forceRefresh || !fetchedAt || Date.now() - fetchedAt > CACHE_TTL_MS) await refresh();
        return cache.get(kid) ?? null;
    };
}
