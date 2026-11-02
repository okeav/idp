// `resolveAuthContext` is the one hook whose return value the caller actually
// uses (it builds `claims`) — it's a data-returning callback, not a one-way
// event notification, so it's never wrapped for webhook dispatch.
const EXCLUDED_HOOKS = new Set(['resolveAuthContext']);

/**
 * Payload fields that are credentials: whoever holds one can reset a password, log in, or verify an
 * address. They are stripped from webhook deliveries unless the endpoint sets `includeCredentials`
 * (e.g. the endpoint that actually sends your emails).
 */
export const CREDENTIAL_FIELDS = Object.freeze({
    onPasswordResetRequested: ['resetToken'],
    onMagicLinkRequested: ['magicLinkToken'],
    onVerificationEmailRequested: ['verificationToken', 'verificationCode'],
});

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
 *
 * The webhook is dispatched even when the in-process hook throws: one failing consumer
 * callback must not silently drop the event for every webhook receiver.
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
            try {
                return await fn(payload);
            } finally {
                const event = name === 'onAuditLog' && payload?.action ? payload.action : name;
                dispatcher.dispatch(event, payload, { credentialFields: CREDENTIAL_FIELDS[name] ?? [] });
            }
        };
    }
    return wrapped;
}
