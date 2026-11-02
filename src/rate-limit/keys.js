import net from 'net';

/**
 * The part of a client IP that identifies one client for rate limiting. IPv4 as-is (an IPv4-mapped
 * IPv6 address `::ffff:a.b.c.d` is IPv4); IPv6 collapsed to its /64 prefix — a single host is
 * routinely handed a whole /64, so keying on the full address gives an attacker 2^64 fresh buckets.
 *
 * `req.ip` is only as good as Express's `trust proxy` setting: set it to your proxy hop count or
 * subnet (never `true`, which trusts any client-supplied X-Forwarded-For).
 */
export function ipKey(ip) {
    if (typeof ip !== 'string' || ip.length === 0) return 'unknown';
    const mapped = ip.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i);
    if (mapped) return mapped[1];
    if (net.isIPv6(ip)) {
        const [head] = ip.split('%'); // drop a zone id
        const expanded = expandIpv6(head);
        return expanded ? `${expanded.slice(0, 4).join(':')}::/64` : head;
    }
    return ip;
}

function expandIpv6(addr) {
    const halves = addr.split('::');
    if (halves.length > 2) return null;
    const left = halves[0] ? halves[0].split(':') : [];
    const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
    const missing = 8 - left.length - right.length;
    if (missing < 0 || (halves.length === 1 && missing !== 0)) return null;
    return [...left, ...Array(halves.length === 2 ? missing : 0).fill('0'), ...right].map((h) => h.toLowerCase().replace(/^0+(?=.)/, ''));
}

/** Per-address rate-limit keys use the email's keyed hash: limiter backends (Redis) and logs never see the address. */
export function emailKey(state, email) {
    return state.hashEmail(email) ?? 'none';
}
