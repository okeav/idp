import { IdpError } from '../errors/idp-error.js';

/** Works unchanged on Express 4 and 5 — `req.body` is writable on both. */
export function validateBody(schema) {
    if (!schema || typeof schema.parse !== 'function') {
        throw new Error('validateBody expects a zod schema (an object with .parse())');
    }
    return function (req, _res, next) {
        try {
            req.body = schema.parse(req.body);
            next();
        } catch (err) {
            next(new IdpError({ code: 'VALIDATION_ERROR', httpStatus: 400, message: 'Request body validation failed', cause: err }));
        }
    };
}
