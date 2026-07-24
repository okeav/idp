import { z } from 'zod';

export const authorizeQuerySchema = z.object({
    client_id: z.string().min(1),
    redirect_uri: z.string().url(),
    response_type: z.string(),
    scope: z.string().optional(),
    state: z.string().optional(),
    code_challenge: z.string().optional(),
    code_challenge_method: z.enum(['S256', 'plain']).optional(),
});

export const confirmAuthorizeSchema = z.object({
    client_id: z.string().min(1),
    redirect_uri: z.string().url(),
    scope: z.string().optional(),
    state: z.string().optional(),
    code_challenge: z.string().optional(),
    code_challenge_method: z.enum(['S256', 'plain']).optional(),
}).strict();

export const denyAuthorizeSchema = z.object({
    redirect_uri: z.string().url(),
    state: z.string().optional(),
    client_id: z.string().optional(),
}).strict();

export const tokenSchema = z.object({
    grant_type: z.enum(['authorization_code', 'refresh_token', 'client_credentials']),
    code: z.string().optional(),
    redirect_uri: z.string().optional(),
    client_id: z.string().min(1),
    client_secret: z.string().optional(),
    code_verifier: z.string().optional(),
    refresh_token: z.string().optional(),
    scope: z.string().optional(),
    nonce: z.string().optional(),
}).passthrough();

export const revokeTokenSchema = z.object({
    token: z.string().min(1),
    token_type_hint: z.string().optional(),
    client_id: z.string().optional(),
    client_secret: z.string().optional(),
}).strict();

export const introspectTokenSchema = z.object({ token: z.string().optional() }).strict();

export const registerOAuthClientSchema = z.object({
    name: z.string().trim().min(1),
    slug: z.string().trim().min(1).toLowerCase(),
    clientType: z.enum(['confidential', 'public']).optional(),
    redirectUris: z.array(z.string().url()).min(1),
    allowedScopes: z.array(z.string()).optional(),
    allowedGrants: z.array(z.enum(['authorization_code', 'client_credentials', 'refresh_token'])).optional(),
    metadata: z.record(z.string(), z.unknown()).optional(),
}).strict();

export const updateOAuthClientSchema = z.object({
    name: z.string().trim().min(1).optional(),
    redirectUris: z.array(z.string().url()).optional(),
    allowedScopes: z.array(z.string()).optional(),
    allowedGrants: z.array(z.enum(['authorization_code', 'client_credentials', 'refresh_token'])).optional(),
    clientType: z.enum(['confidential', 'public']).optional(),
    accessTokenTTL: z.number().int().positive().optional(),
    refreshTokenTTL: z.number().int().positive().optional(),
    idTokenTTL: z.number().int().positive().optional(),
    logoUrl: z.string().url().optional(),
    websiteUrl: z.string().url().optional(),
    privacyPolicyUrl: z.string().url().optional(),
    termsOfServiceUrl: z.string().url().optional(),
    supportEmail: z.string().email().optional(),
    metadata: z.record(z.string(), z.unknown()).optional(),
}).strict();
