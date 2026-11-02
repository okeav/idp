const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);
// RFC 8252 §7.1 private-use URI scheme for native apps: reverse-DNS, so it contains a dot (com.example.app:/cb).
const PRIVATE_USE_SCHEME = /^[a-z][a-z0-9+-]*(\.[a-z0-9+-]+)+:$/;

/**
 * Whether `uri` may be registered as a client redirect URI. The authorization code is sent there, so:
 * - `https:` — always;
 * - `http:` — only to a loopback host (native apps and local development, RFC 8252 §7.3);
 * - a reverse-DNS private-use scheme (`com.example.app:/callback`) for native apps;
 * - never a fragment (RFC 6749 §3.1.2), embedded credentials, or any other scheme (`javascript:`,
 *   `data:`, `file:` …).
 */
export function isAcceptableRedirectUri(uri) {
    if (typeof uri !== 'string' || uri.length > 2048 || uri.includes('#')) return false;
    let url;
    try {
        url = new URL(uri);
    } catch {
        return false;
    }
    if (url.username || url.password) return false;
    if (url.protocol === 'https:') return Boolean(url.hostname);
    if (url.protocol === 'http:') return LOOPBACK_HOSTS.has(url.hostname);
    return PRIVATE_USE_SCHEME.test(url.protocol);
}
