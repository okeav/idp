import { IdpError } from '../errors/idp-error.js';

/**
 * Express 5 makes `req.query` a read-only getter, so it can't be reassigned
 * the way `validateBody` reassigns `req.body` (this broke in the audited
 * source's Express-5 upgrade). Storing the parsed result on
 * `req.validatedQuery` instead works unchanged on both Express 4 and 5 —
 * handlers read `req.validatedQuery`, not `req.query`, after this runs.
 */
export function validateQuery(schema) {
    if (!schema || typeof schema.parse !== 'function') {
        throw new Error('validateQuery expects a zod schema (an object with .parse())');
    }
    return function (req, _res, next) {
        try {
            req.validatedQuery = schema.parse(req.query);
            next();
        } catch (err) {
            next(new IdpError({ code: 'VALIDATION_ERROR', httpStatus: 400, message: 'Request query validation failed', cause: err }));
        }
    };
}
