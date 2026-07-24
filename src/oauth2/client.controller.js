import { getState } from '../config/state.js';
import { IdpError } from '../errors/idp-error.js';
import { OAUTH_CLIENT_STATUS, CLIENT_TYPES } from '../config/constants.js';
import { generateClientId, generateClientSecret, hashClientSecret } from '../utils/oauth-client-credentials.js';
import { auditLog } from '../hooks/index.js';

/** POST /oauth2/clients — public self-registration; lands PENDING_APPROVAL until an operator approves it. */
export async function registerOAuthClientHandler(req, res, next) {
    try {
        const state = getState();
        const { name, slug, clientType, redirectUris, allowedScopes, allowedGrants, metadata } = req.body;

        const existing = await state.storage.oauthClientRepository.findBySlug(slug);
        if (existing) throw new IdpError({ code: 'OAUTH_CLIENT_EXISTS', httpStatus: 409, message: 'A client with this slug already exists' });

        const clientId = generateClientId();
        const clientSecret = generateClientSecret();
        const clientSecretHash = await hashClientSecret(clientSecret);

        const client = await state.storage.oauthClientRepository.create({
            name, slug, clientId, clientSecretHash,
            clientType: clientType || CLIENT_TYPES.CONFIDENTIAL,
            redirectUris,
            allowedScopes: allowedScopes || ['openid', 'email', 'profile'],
            allowedGrants: allowedGrants || ['authorization_code', 'refresh_token'],
            metadata: metadata || {},
            status: OAUTH_CLIENT_STATUS.PENDING_APPROVAL,
        });

        await auditLog(state.logger, state.hooks, 'OAUTH_CLIENT_REGISTERED', { clientId, slug });
        res.status(201).json({ id: client.id, name: client.name, slug: client.slug, clientId, clientSecret, status: client.status });
    } catch (err) {
        next(err);
    }
}

export async function getOAuthClientHandler(req, res, next) {
    try {
        const state = getState();
        const client = await state.storage.oauthClientRepository.findByClientId(req.params.clientId);
        if (!client) throw new IdpError({ code: 'OAUTH_CLIENT_NOT_FOUND', httpStatus: 404, message: `Client ${req.params.clientId} not found` });
        res.json(client);
    } catch (err) {
        next(err);
    }
}

export async function listOAuthClientsHandler(req, res, next) {
    try {
        const state = getState();
        const page = Math.max(1, parseInt(req.query.page) || 1);
        const limit = Math.min(100, Math.max(1, parseInt(req.query.limit) || 20));
        const [clients, total] = await Promise.all([
            state.storage.oauthClientRepository.listMany({ skip: (page - 1) * limit, limit }),
            state.storage.oauthClientRepository.countAll(),
        ]);
        res.json({ clients, total, page, limit });
    } catch (err) {
        next(err);
    }
}

export async function updateOAuthClientHandler(req, res, next) {
    try {
        const state = getState();
        const client = await state.storage.oauthClientRepository.updateByClientId(req.params.clientId, req.body);
        if (!client) throw new IdpError({ code: 'OAUTH_CLIENT_NOT_FOUND', httpStatus: 404, message: `Client ${req.params.clientId} not found` });

        await auditLog(state.logger, state.hooks, 'OAUTH_CLIENT_UPDATED', { clientId: req.params.clientId });
        res.json({ clientId: client.clientId, name: client.name, status: client.status });
    } catch (err) {
        next(err);
    }
}

export async function rotateOAuthClientSecretHandler(req, res, next) {
    try {
        const state = getState();
        const client = await state.storage.oauthClientRepository.findByClientId(req.params.clientId);
        if (!client) throw new IdpError({ code: 'OAUTH_CLIENT_NOT_FOUND', httpStatus: 404, message: `Client ${req.params.clientId} not found` });

        const newSecret = generateClientSecret();
        await state.storage.oauthClientRepository.updateByClientId(req.params.clientId, { clientSecretHash: await hashClientSecret(newSecret) });

        await auditLog(state.logger, state.hooks, 'OAUTH_CLIENT_SECRET_ROTATED', { clientId: req.params.clientId });
        res.json({ clientId: req.params.clientId, clientSecret: newSecret });
    } catch (err) {
        next(err);
    }
}

export async function deactivateOAuthClientHandler(req, res, next) {
    try {
        const state = getState();
        const client = await state.storage.oauthClientRepository.updateByClientId(req.params.clientId, { status: OAUTH_CLIENT_STATUS.INACTIVE });
        if (!client) throw new IdpError({ code: 'OAUTH_CLIENT_NOT_FOUND', httpStatus: 404, message: `Client ${req.params.clientId} not found` });

        await auditLog(state.logger, state.hooks, 'OAUTH_CLIENT_DEACTIVATED', { clientId: req.params.clientId });
        res.json({ clientId: req.params.clientId, status: client.status });
    } catch (err) {
        next(err);
    }
}

export async function approveOAuthClientHandler(req, res, next) {
    try {
        const state = getState();
        const client = await state.storage.oauthClientRepository.updateByClientId(req.params.clientId, { status: OAUTH_CLIENT_STATUS.ACTIVE });
        if (!client) throw new IdpError({ code: 'OAUTH_CLIENT_NOT_FOUND', httpStatus: 404, message: `Client ${req.params.clientId} not found` });

        await auditLog(state.logger, state.hooks, 'OAUTH_CLIENT_APPROVED', { clientId: req.params.clientId });
        res.json({ clientId: req.params.clientId, status: client.status });
    } catch (err) {
        next(err);
    }
}
