import crypto from 'crypto';

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
 * Decides whether the current login is from a device this user hasn't
 * authenticated from before, and fires `onNewDeviceLogin` if so. Skipped on
 * a user's very first-ever login (nothing to compare against, and the
 * alert adds no value right after signup).
 */
export async function detectAndNotifyNewDevice({ sessionRepository, hooks, logger, req, user, wasFirstLogin }) {
    const currentDeviceInfo = req.headers?.['user-agent'] || '';
    const fingerprint = buildDeviceFingerprint(currentDeviceInfo);

    if (wasFirstLogin || !currentDeviceInfo) return { isNewDevice: false, deviceFingerprint: fingerprint };

    const known = await sessionRepository.existsForDevice(user.id, fingerprint, currentDeviceInfo);
    const isNewDevice = !known;
    if (!isNewDevice) return { isNewDevice, deviceFingerprint: fingerprint };

    const { safeInvokeHook } = await import('../hooks/index.js');
    await safeInvokeHook(logger, hooks, 'onNewDeviceLogin', {
        userId: String(user.id),
        email: user.email,
        firstName: user.profile?.firstName || '',
        lastName: user.profile?.lastName || '',
        locale: user.profile?.locale || 'en',
        when: new Date().toISOString(),
        deviceInfo: currentDeviceInfo,
        ipAddress: req.ip || '',
    });

    return { isNewDevice, deviceFingerprint: fingerprint };
}
