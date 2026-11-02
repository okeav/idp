import { z } from 'zod';
import { isAcceptableRedirectUri } from './redirect-uri.js';

const httpsUrl = (field) => z.string().max(2048).refine((v) => { try { return new URL(v).protocol === 'https:'; } catch { return false; } }, `${field} must be an https URL`);

// PKCE (RFC 7636): only S256. A challenge is the base64url SHA-256 of the verifier (always 43
// chars); a verifier is 43–128 unreserved characters. `plain` is refused — it protects nothing
// once the authorization request is observed (RFC 9700 §2.1.1).
const codeChallenge = z.string().regex(/^[A-Za-z0-9_-]{43}$/, 'code_challenge must be a base64url-encoded SHA-256 (S256) value');
const codeVerifier = z.string().regex(/^[A-Za-z0-9\-._~]{43,128}$/, 'code_verifier must be 43-128 unreserved characters');
const pkceFields = {
    code_challenge: codeChallenge.optional(),
    code_challenge_method: z.literal('S256').optional(),
};
// RFC 7636 §4.3: an omitted method means "plain" — so a challenge without `S256` is refused, not assumed.
const pkceMethodRequired = (v) => !v.code_challenge || v.code_challenge_method === 'S256';
const pkceMethodMessage = { message: 'code_challenge_method=S256 is required with a code_challenge', path: ['code_challenge_method'] };

const redirectUri = z.string().refine(isAcceptableRedirectUri, { message: 'redirect_uri must be https (http only for loopback), or a reverse-DNS private-use scheme, with no fragment' });
const nonce = z.string().min(1).max(512);

export const authorizeQuerySchema = z.object({
    client_id: z.string().min(1),
    redirect_uri: z.string().url(),
    response_type: z.string(),
    scope: z.string().optional(),
    state: z.string().max(2048).optional(),
    nonce: nonce.optional(),
    // OIDC Core §3.1.2.1 — see authorize.controller.js (resolvePrompt).
    prompt: z.string().max(100).optional(),
    max_age: z.string().regex(/^\d{1,10}$/, 'max_age must be a non-negative integer of seconds').optional(),
    ...pkceFields,
}).refine(pkceMethodRequired, pkceMethodMessage);

// Confirm/deny act on the request stored under the consent_challenge that /oauth2/authorize
// returned — the client, scopes, redirect_uri, state, nonce and PKCE challenge are NOT taken from
// this body (see authorize.controller.js).
const consentChallenge = z.string().regex(/^[A-Za-z0-9_-]{20,100}$/, 'consent_challenge is malformed');
export const confirmAuthorizeSchema = z.object({ consent_challenge: consentChallenge }).strict();
export const denyAuthorizeSchema = z.object({ consent_challenge: consentChallenge }).strict();

// client_id / client_secret may instead arrive as HTTP Basic credentials (client_secret_basic).
export const tokenSchema = z.object({
    grant_type: z.enum(['authorization_code', 'refresh_token', 'client_credentials']),
    code: z.string().optional(),
    redirect_uri: z.string().optional(),
    client_id: z.string().min(1).optional(),
    client_secret: z.string().optional(),
    code_verifier: codeVerifier.optional(),
    refresh_token: z.string().optional(),
    scope: z.string().optional(),
}).passthrough();

export const revokeTokenSchema = z.object({
    token: z.string().min(1),
    token_type_hint: z.string().optional(),
    client_id: z.string().min(1).optional(),
    client_secret: z.string().optional(),
}).strict();

export const introspectTokenSchema = z.object({
    token: z.string().min(1),
    token_type_hint: z.string().optional(),
    client_id: z.string().min(1).optional(),
    client_secret: z.string().optional(),
}).strict();

export const consentQuerySchema = z.object({ client_id: z.string().min(1) }).strict();

export const registerOAuthClientSchema = z.object({
    name: z.string().trim().min(1),
    slug: z.string().trim().min(1).toLowerCase(),
    clientType: z.enum(['confidential', 'public']).optional(),
    redirectUris: z.array(redirectUri).min(1),
    postLogoutRedirectUris: z.array(redirectUri).optional(),
    allowedScopes: z.array(z.string()).optional(),
    allowedGrants: z.array(z.enum(['authorization_code', 'client_credentials', 'refresh_token'])).optional(),
    metadata: z.record(z.string(), z.unknown()).optional(),
}).strict();

export const updateOAuthClientSchema = z.object({
    name: z.string().trim().min(1).optional(),
    redirectUris: z.array(redirectUri).optional(),
    postLogoutRedirectUris: z.array(redirectUri).optional(),
    allowedScopes: z.array(z.string()).optional(),
    allowedGrants: z.array(z.enum(['authorization_code', 'client_credentials', 'refresh_token'])).optional(),
    clientType: z.enum(['confidential', 'public']).optional(),
    // Bounded: an access token can't be revoked once issued (client_credentials tokens have no session),
    // so a ten-year lifetime is a ten-year credential.
    accessTokenTTL: z.number().int().positive().max(24 * 60 * 60).optional(),
    refreshTokenTTL: z.number().int().positive().max(365 * 24 * 60 * 60).optional(),
    idTokenTTL: z.number().int().positive().max(24 * 60 * 60).optional(),
    // Shown as links on the consent screen: https only (a `javascript:` URL there runs in the IdP's origin).
    logoUrl: httpsUrl('logoUrl').optional(),
    websiteUrl: httpsUrl('websiteUrl').optional(),
    privacyPolicyUrl: httpsUrl('privacyPolicyUrl').optional(),
    termsOfServiceUrl: httpsUrl('termsOfServiceUrl').optional(),
    supportEmail: z.string().email().optional(),
    metadata: z.record(z.string(), z.unknown()).optional(),
}).strict();
