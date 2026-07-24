import { getState } from '../config/state.js';
import { IdpError } from '../errors/idp-error.js';
import { buildUserTokenJwks } from './jwks.js';
import { KEY_STATUS } from '../config/constants.js';

/** GET /.well-known/jwks.json — RFC 7517 JWK Set for this IDP's user-token signing keys. */
export function jwksHandler(_req, res) {
    res.json(buildUserTokenJwks(getState()));
}

/** GET /keys/:kid — raw base64 PEM for a single key. Internal use (e.g. resource servers that want the PEM directly instead of JWK). */
export function authPublicKeyHandler(req, res, next) {
    try {
        const state = getState();
        const { kid } = req.params;
        const entry = state.signingKeys[kid];
        if (!entry) throw new IdpError({ code: 'UNKNOWN_KID', httpStatus: 404, message: 'Unknown key ID' });
        if (![KEY_STATUS.ACTIVE, KEY_STATUS.ROTATING, KEY_STATUS.RETIRED].includes(entry.status)) {
            throw new IdpError({ code: 'KEY_NOT_ALLOWED', httpStatus: 403, message: 'Key not allowed' });
        }
        res.json({ publicKey: Buffer.from(entry.publicKeyPem, 'utf8').toString('base64') });
    } catch (err) {
        next(err);
    }
}
