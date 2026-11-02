import crypto from 'crypto';
import { safeInvokeHook } from '../hooks/index.js';

/**
 * Reduces a raw user-agent string to a stable "browser-family + os-family"
 * fingerprint so a browser/OS auto-update doesn't trigger a false
 * new-device alert on every login. Narrower than full device identity —
 * switching browsers on the same machine is treated as a new device, which
 * is the conservative/correct choice.
 */
export function normalizeUserAgent(ua) {
    if (!ua || typeof ua !== 'string') return '';
    const lower = ua.toLowerCase().trim();

    const browser =
        /edg\//.test(lower) ? 'edge' :
        /opr\/|opera/.test(lower) ? 'opera' :
        /chrome\//.test(lower) ? 'chrome' :
        /firefox\//.test(lower) ? 'firefox' :
        /safari\//.test(lower) ? 'safari' :
        /msie |trident\//.test(lower) ? 'ie' :
        null;

    const os =
        /windows nt/.test(lower) ? 'windows' :
        /mac os x|macintosh/.test(lower) ? 'macos' :
        /android/.test(lower) ? 'android' :
        /iphone|ipad|ios/.test(lower) ? 'ios' :
        /linux/.test(lower) ? 'linux' :
        null;

    if (browser && os) return `${browser}|${os}`;
    return lower;
}

export function buildDeviceFingerprint(rawUserAgent) {
    const normalized = normalizeUserAgent(rawUserAgent);
    if (!normalized) return null;
    return crypto.createHash('sha256').update(normalized).digest('hex');
}

/**
 * Fires `onNewDeviceLogin`. Whether the device is new is decided by the caller BEFORE the login's own
 * session row is written (see issueSession) — checking afterwards always finds that row, which is
 * why the alert never fired before 0.4.0.
 */
export async function notifyNewDevice({ hooks, logger, req, user }) {
    await safeInvokeHook(logger, hooks, 'onNewDeviceLogin', {
        userId: String(user.id),
        email: user.email,
        firstName: user.profile?.firstName || '',
        lastName: user.profile?.lastName || '',
        locale: user.profile?.locale || 'en',
        when: new Date().toISOString(),
        deviceInfo: req.headers?.['user-agent'] || '',
        ipAddress: req.ip || '',
    });
}
