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

// A hook is waited for at most this long (`config.hookTimeoutMs`, default 10 s). It keeps running in
// the background afterwards, but a hung consumer callback (a stalled mail API, say) can't hold a
// login or a token response hostage.
let hookTimeoutMs = 10_000;
export function setHookTimeout(ms) {
    hookTimeoutMs = ms;
}

/**
 * Invokes a hook without letting it affect the caller: awaits it — up to the hook timeout — (so async
 * hooks normally complete before the process could exit, e.g. serverless) but swallows and logs
 * any rejection/throw rather than propagating it into the request lifecycle. A misbehaving consumer
 * hook must never break login.
 */
export async function safeInvokeHook(logger, hooks, hookName, payload) {
    const fn = hooks?.[hookName];
    if (typeof fn !== 'function') return;
    let timer;
    try {
        const timeout = new Promise((resolve) => {
            timer = setTimeout(() => {
                logger?.warn?.({ hook: hookName, timeoutMs: hookTimeoutMs }, `Hook "${hookName}" is still running — not waiting for it`);
                resolve();
            }, hookTimeoutMs);
            timer.unref?.();
        });
        await Promise.race([Promise.resolve(fn(payload)), timeout]);
    } catch (err) {
        logger?.warn?.({ err, hook: hookName }, `Hook "${hookName}" threw — ignoring`);
    } finally {
        clearTimeout(timer);
    }
}

/**
 * Starts a hook without waiting for it at all. For the notifications on endpoints that must not
 * reveal whether an account exists (register, resend verification, forgot password, magic link):
 * if the response waited for the hook — which typically sends an email — it would come back
 * measurably later for a known address than for an unknown one. The hook itself is still called
 * synchronously (its first synchronous step runs before the response); only its promise is not
 * awaited. In a serverless runtime, make such hooks hand off quickly (enqueue, don't send inline).
 */
export function invokeHookDetached(logger, hooks, hookName, payload) {
    safeInvokeHook(logger, hooks, hookName, payload).catch(() => { /* safeInvokeHook never rejects */ });
}

export function auditLog(logger, hooks, action, payload) {
    return safeInvokeHook(logger, hooks, 'onAuditLog', { action, ...payload, timestamp: new Date().toISOString() });
}

/** auditLog, not awaited — for the same enumeration-sensitive endpoints as invokeHookDetached. */
export function auditLogDetached(logger, hooks, action, payload) {
    invokeHookDetached(logger, hooks, 'onAuditLog', { action, ...payload, timestamp: new Date().toISOString() });
}
