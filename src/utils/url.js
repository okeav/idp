const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]']);

export const isLoopbackHost = (host) => LOOPBACK.has(host);

/** https, or http to this machine (development). */
export function isSecureUrl(value) {
    try {
        const url = new URL(value);
        return url.protocol === 'https:' || (url.protocol === 'http:' && LOOPBACK.has(url.hostname));
    } catch {
        return false;
    }
}
