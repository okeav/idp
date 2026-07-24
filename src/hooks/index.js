/**
 * All hooks are optional and default to no-ops. They replace every
 * `publishEvent(...)` call the audited Okeav auth-service made against
 * RabbitMQ — this package never talks to a message bus itself; a hook
 * implementation can publish to one if the consumer wants that.
 *
 * `onAuditLog` is a single generic firehose covering every audit-style event
 * (login, logout, password change, MFA changes, OAuth2/OIDC/SSO/admin
 * actions, etc.) — see README "Event hooks" table for the full list of
 * `action` values it's called with. The five `on*` notification hooks below
 * are the only ones that carry a payload rich enough to actually send a
 * notification (email/SMS/push) and so get their own named callback.
 */
export function defaultHooks() {
    return {
        onAuditLog: () => {},
        onVerificationEmailRequested: () => {},
        onPasswordResetRequested: () => {},
        onPasswordChanged: () => {},
        onSuspiciousActivityDetected: () => {},
        onNewDeviceLogin: () => {},
        onMagicLinkRequested: () => {},
    };
}

export function mergeHooks(userHooks = {}) {
    return { ...defaultHooks(), ...userHooks };
}

/**
 * Invokes a hook without letting it affect the caller: awaits it (so async
 * hooks complete before the process could exit, e.g. serverless) but
 * swallows and logs any rejection/throw rather than propagating it into the
 * request lifecycle. A misbehaving consumer hook must never break login.
 */
export async function safeInvokeHook(logger, hooks, hookName, payload) {
    const fn = hooks?.[hookName];
    if (typeof fn !== 'function') return;
    try {
        await fn(payload);
    } catch (err) {
        logger?.warn?.({ err, hook: hookName }, `Hook "${hookName}" threw — ignoring`);
    }
}

export function auditLog(logger, hooks, action, payload) {
    return safeInvokeHook(logger, hooks, 'onAuditLog', { action, ...payload, timestamp: new Date().toISOString() });
}
