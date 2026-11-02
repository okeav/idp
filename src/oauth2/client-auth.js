import { IdpError } from '../errors/idp-error.js';
import { OAUTH_CLIENT_STATUS, CLIENT_TYPES } from '../config/constants.js';
import { verifyClientSecret, hashClientSecret } from '../utils/oauth-client-credentials.js';
import { tokenHashKeys, HASH_PURPOSES } from '../signing/token.service.js';

/**
 * One answer for every client-authentication failure — unknown client, inactive client, missing or
 * wrong secret — so the token endpoint doesn't reveal which client ids exist (RFC 6749 §5.2
 * `invalid_client`).
 */
export const INVALID_CLIENT = () => new IdpError({ code: 'INVALID_CLIENT', httpStatus: 401, message: 'Client authentication failed' });

/** `application/x-www-form-urlencoded` decoding, as RFC 6749 §2.3.1 requires for Basic credentials. */
function formDecode(s) {
    return decodeURIComponent(s.replace(/\+/g, ' '));
}

/**
 * The client credentials on a token-endpoint request: HTTP Basic (`client_secret_basic`) or the
 * body (`client_secret_post`, or `client_id` alone for a public client). Using both Basic and a body
 * secret is refused (RFC 6749 §2.3: one method per request), as is a body `client_id` that differs
 * from the Basic one.
 */
export function readClientCredentials(req) {
    const header = req.headers?.authorization;
    const bodyId = req.body?.client_id;
    const bodySecret = req.body?.client_secret;

    if (typeof header === 'string' && /^Basic\s+/i.test(header)) {
        let id;
        let secret;
        try {
            const decoded = Buffer.from(header.replace(/^Basic\s+/i, '').trim(), 'base64').toString('utf8');
            const sep = decoded.indexOf(':');
            if (sep < 0) throw new Error('no separator');
            id = formDecode(decoded.slice(0, sep));
            secret = formDecode(decoded.slice(sep + 1));
        } catch {
            throw INVALID_CLIENT();
        }
        if (!id) throw INVALID_CLIENT();
        if (bodySecret !== undefined) throw new IdpError({ code: 'INVALID_REQUEST', httpStatus: 400, message: 'Use one client authentication method per request' });
        if (bodyId !== undefined && bodyId !== id) throw INVALID_CLIENT();
        return { clientId: id, clientSecret: secret };
    }
    return { clientId: bodyId, clientSecret: bodySecret };
}

/**
 * Authenticates the calling client. A confidential client must present its secret; a public client
 * presents only its id (and is refused when `requireConfidential`). A secret still stored as a
 * pre-0.4.0 bcrypt hash is re-stored as HMAC after it verifies.
 */
export async function authenticateClient(state, req, { requireConfidential = false } = {}) {
    const { clientId, clientSecret } = readClientCredentials(req);
    if (!clientId || typeof clientId !== 'string') throw INVALID_CLIENT();

    const repo = state.storage.oauthClientRepository;
    const client = await repo.findByClientId(clientId, { includeSecret: true });
    if (!client || client.status !== OAUTH_CLIENT_STATUS.ACTIVE) throw INVALID_CLIENT();

    if (client.clientType === CLIENT_TYPES.CONFIDENTIAL) {
        const keys = tokenHashKeys(state, HASH_PURPOSES.OAUTH_CLIENT_SECRET);
        const { valid, upgrade } = clientSecret ? await verifyClientSecret(clientSecret, client.clientSecretHash, keys) : { valid: false };
        if (!valid) throw INVALID_CLIENT();
        if (upgrade) {
            try {
                await repo.updateByClientId(clientId, { clientSecretHash: hashClientSecret(clientSecret, keys[0]) });
            } catch (err) {
                state.logger?.warn?.({ err, clientId }, 'Could not upgrade a legacy client-secret hash (non-fatal)');
            }
        }
    } else if (requireConfidential) {
        throw INVALID_CLIENT();
    }
    return client;
}
