const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]']);

export const isLoopbackHost = (host) => LOOPBACK.has(host);

/**
 * https, or http to this machine — or any http with NODE_ENV=development (a docker-compose service
 * name such as http://idp:4000). Elsewhere an unset NODE_ENV counts as production.
 */
export function isSecureUrl(value) {
    try {
        const url = new URL(value);
        if (url.protocol === 'https:') return true;
        return url.protocol === 'http:' && (LOOPBACK.has(url.hostname) || process.env.NODE_ENV === 'development');
    } catch {
        return false;
    }
}
