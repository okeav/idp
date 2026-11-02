import { getState } from '../config/state.js';
import { IdpError } from '../errors/idp-error.js';
import { auditLog } from '../hooks/index.js';
import { OAUTH_CLIENT_STATUS, CACHE_KEY_PREFIXES } from '../config/constants.js';

/** Revokes the client's live sessions (one user's, or everyone's) and marks their access tokens revoked in the cache too. */
export async function revokeClientSessions(state, clientId, { userId } = {}) {
    if (typeof state.storage.sessionRepository.revokeForClient !== 'function') {
        state.logger?.warn?.({ clientId }, 'Storage adapter has no sessionRepository.revokeForClient() — tokens issued to the client were NOT revoked');
        return 0;
    }
    const { revokedCount, jtis } = await state.storage.sessionRepository.revokeForClient(clientId, { userId });
    for (const jti of jtis || []) await state.cache.set(`${CACHE_KEY_PREFIXES.REVOKED_REFRESH_TOKEN}:${jti}`, '1', state.config.ttls.revocationCache);
    return revokedCount;
}

/** GET /oauth2/consent — pending-consent details for a client */
export async function getConsentHandler(req, res, next) {
    try {
        const state = getState();
        const clientId = (req.validatedQuery || req.query).client_id;
        if (!req.auth?.userId) throw new IdpError({ code: 'UNAUTHENTICATED', httpStatus: 401, message: 'Authentication required' });
        if (!clientId) throw new IdpError({ code: 'MISSING_REQUIRED_FIELDS', httpStatus: 400, message: 'client_id is required' });

        const client = await state.storage.oauthClientRepository.findByClientId(clientId);
        if (!client || client.status !== OAUTH_CLIENT_STATUS.ACTIVE) throw new IdpError({ code: 'OAUTH_CLIENT_NOT_FOUND', httpStatus: 400, message: 'Unknown client' });

        const existingConsent = await state.storage.consentRepository.find(req.auth.userId, clientId);
        res.json({
            client: { name: client.name, clientId: client.clientId, logoUrl: client.logoUrl, websiteUrl: client.websiteUrl, privacyPolicyUrl: client.privacyPolicyUrl },
            existingConsent: existingConsent ? { scopes: existingConsent.scopes, grantedAt: existingConsent.grantedAt } : null,
        });
    } catch (err) {
        next(err);
    }
}

export async function listConsentsHandler(req, res, next) {
    try {
        const state = getState();
        if (!req.auth?.userId) throw new IdpError({ code: 'UNAUTHENTICATED', httpStatus: 401, message: 'Authentication required' });

        const consents = await state.storage.consentRepository.listForUser(req.auth.userId);
        res.json(consents.map((c) => ({ clientId: c.clientId, scopes: c.scopes, grantedAt: c.grantedAt, expiresAt: c.expiresAt })));
    } catch (err) {
        next(err);
    }
}

export async function revokeConsentHandler(req, res, next) {
    try {
        const state = getState();
        if (!req.auth?.userId) throw new IdpError({ code: 'UNAUTHENTICATED', httpStatus: 401, message: 'Authentication required' });

        await state.storage.consentRepository.revoke(req.auth.userId, req.params.clientId);
        // Withdrawing consent also ends what it authorized: the client's tokens for this user.
        const revokedSessions = await revokeClientSessions(state, req.params.clientId, { userId: req.auth.userId });
        await auditLog(state.logger, state.hooks, 'CONSENT_REVOKED', { userId: req.auth.userId, clientId: req.params.clientId, revokedSessions });
        res.json({ status: 'ok' });
    } catch (err) {
        next(err);
    }
}
