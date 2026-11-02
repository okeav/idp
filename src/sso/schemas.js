import { z } from 'zod';
import { loginChallengeSchema } from '../oauth2/login-challenge.js';

export const ssoInitiateQuerySchema = z.object({
    redirect_uri: z.string().url(),
    login_challenge: loginChallengeSchema.optional(),
}).passthrough(); // extra opaque query params are forwarded to resolveAuthContext — see initiate.controller.js
