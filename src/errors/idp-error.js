/**
 * The package's only error type. Handlers throw this (or let it propagate
 * from `next(err)` in middleware) and never shape an HTTP response body
 * themselves — the consumer's own Express error-handling middleware maps
 * `{ code, httpStatus, message }` to whatever envelope their API uses.
 */
export class IdpError extends Error {
    constructor({ code, httpStatus = 500, message, cause } = {}) {
        super(message || code || 'IdpError');
        this.name = 'IdpError';
        this.code = code || 'INTERNAL_ERROR';
        this.httpStatus = httpStatus;
        if (cause !== undefined) this.cause = cause;
        Error.captureStackTrace?.(this, IdpError);
    }
}

export function isIdpError(err) {
    return err instanceof IdpError;
}
