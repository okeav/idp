import { getState } from '../config/state.js';
/**
 * The package's only error type. Handlers throw this (or let it propagate
 * from `next(err)` in middleware) and never shape an HTTP response body
 * themselves — the consumer's own Express error-handling middleware maps
 * `{ code, httpStatus, message }` to whatever envelope their API uses (or
 * mounts `idpErrorHandler()`, which does it safely).
 *
 * `status` / `statusCode` mirror `httpStatus` so Express's default error
 * handler (and other frameworks' conventions) answer with the right status
 * instead of turning every 401/429 into a 500.
 */
export class IdpError extends Error {
    constructor({ code, httpStatus = 500, message, cause } = {}) {
        super(message || code || 'IdpError');
        this.name = 'IdpError';
        this.code = code || 'INTERNAL_ERROR';
        this.httpStatus = httpStatus;
        this.status = httpStatus;
        this.statusCode = httpStatus;
        // Our messages are written for clients; only show them for client errors.
        this.expose = httpStatus < 500;
        if (cause !== undefined) this.cause = cause;
        Error.captureStackTrace?.(this, IdpError);
    }
}

export function isIdpError(err) {
    return err instanceof IdpError;
}

/**
 * An Express error handler that is safe to expose to the internet: mount it after the router.
 *
 * - An `IdpError` below 500 answers `{ error: code, message }`.
 * - Body-parser errors (malformed JSON, payload too large) answer 400/413 with a fixed message —
 *   never the parser's text, which echoes the request body.
 * - Anything else — an IdpError of 500+, a database error, a bug — answers 500
 *   `{ error: 'INTERNAL_ERROR' }` with no message, stack or driver detail (those name collections,
 *   indexes and values), and is logged.
 *
 * @param {{ logger?: { error?: Function } }} [opts]
 */
/**
 * `logger`: where unexpected (5xx) errors are logged — by default the logger given to
 * initIdentityProvider, so they are never silently dropped.
 */
export function idpErrorHandler({ logger } = {}) {
    // eslint-disable-next-line no-unused-vars
    return function (err, req, res, _next) {
        if (res.headersSent) return res.end();
        if (isIdpError(err) && err.httpStatus < 500) {
            return res.status(err.httpStatus).json({ error: err.code, message: err.message });
        }
        if (err?.type === 'entity.too.large' || err?.status === 413) {
            return res.status(413).json({ error: 'PAYLOAD_TOO_LARGE', message: 'Request body is too large' });
        }
        if (err?.type === 'entity.parse.failed' || (err instanceof SyntaxError && err?.status === 400)) {
            return res.status(400).json({ error: 'INVALID_REQUEST', message: 'Malformed request body' });
        }
        // The path only — a query string can carry tokens (end-session's id_token_hint, an SSO code).
        (logger ?? stateLogger())?.error?.({ err, path: req?.path }, 'Unhandled error');
        const status = isIdpError(err) ? err.httpStatus : 500;
        res.status(status).json({ error: isIdpError(err) ? err.code : 'INTERNAL_ERROR' });
    };
}

/** The configured logger, if the IdP is initialized (the error handler may run before init). */
function stateLogger() {
    try {
        return getState().logger;
    } catch {
        return null;
    }
}
