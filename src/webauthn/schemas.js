import { z } from 'zod';

// WebAuthn response bodies are large, deeply-nested JSON objects defined by
// the browser/authenticator (RegistrationResponseJSON / AuthenticationResponseJSON)
// — validated structurally at the top level only (required fields every
// conformant response has) rather than fully modeled field-by-field, which
// would just duplicate @simplewebauthn/server's own parsing and go stale
// against future WebAuthn spec additions.
const webauthnResponseSchema = z.object({
    id: z.string().min(1),
    rawId: z.string().min(1),
    type: z.string().min(1),
    response: z.record(z.string(), z.unknown()),
    clientExtensionResults: z.record(z.string(), z.unknown()).optional(),
}).passthrough();

export const registrationOptionsSchema = z.object({}).strict();

export const verifyRegistrationSchema = z.object({
    response: webauthnResponseSchema,
    name: z.string().max(120).optional(),
}).strict();

export const authenticationOptionsSchema = z.object({
    email: z.string().trim().toLowerCase().email().optional(),
}).strict();

export const verifyAuthenticationSchema = z.object({
    response: webauthnResponseSchema,
}).strict();

export const mfaWebauthnOptionsSchema = z.object({
    mfaChallengeToken: z.string().min(1),
}).strict();

export const verifyMfaWebauthnSchema = z.object({
    mfaChallengeToken: z.string().min(1),
    response: webauthnResponseSchema,
}).strict();
