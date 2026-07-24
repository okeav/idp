/** Default logger — used when the consumer doesn't supply one. Mirrors the pino-style `{ info, warn, error, debug }(obj, msg)` call shape. */
export function createConsoleLogger() {
    const format = (obj, msg) => (obj && Object.keys(obj).length ? [msg, obj] : [msg]);
    return {
        info: (obj, msg) => console.info(...format(obj, msg)),
        warn: (obj, msg) => console.warn(...format(obj, msg)),
        error: (obj, msg) => console.error(...format(obj, msg)),
        debug: (obj, msg) => console.debug(...format(obj, msg)),
    };
}
