// `resolveAuthContext` is the one hook whose return value the caller actually
// uses (it builds `claims`) — it's a data-returning callback, not a one-way
// event notification, so it's never wrapped for webhook dispatch.
const EXCLUDED_HOOKS = new Set(['resolveAuthContext']);

/**
 * Wraps every one-way notification hook so that, in addition to invoking the
 * consumer's in-process hook (unchanged), it also fires an outbound webhook
 * delivery via `dispatcher`. Purely additive — if no webhook endpoints are
 * configured, `dispatcher.isNoop` is true and the original `hooks` object is
 * returned untouched.
 *
 * `onAuditLog` payloads carry their own `action` (e.g. "login", "password.changed"),
 * which is a more useful event name for a consumer filtering deliveries than
 * the literal string "onAuditLog", so that one case uses `payload.action` as
 * the dispatched event name instead of the hook name.
 */
export function wrapHooksWithWebhooks(hooks, dispatcher) {
    if (!dispatcher || dispatcher.isNoop) return hooks;

    const wrapped = {};
    for (const [name, fn] of Object.entries(hooks)) {
        if (EXCLUDED_HOOKS.has(name) || typeof fn !== 'function') {
            wrapped[name] = fn;
            continue;
        }
        wrapped[name] = async (payload) => {
            const result = await fn(payload);
            const event = name === 'onAuditLog' && payload?.action ? payload.action : name;
            dispatcher.dispatch(event, payload);
            return result;
        };
    }
    return wrapped;
}
