import { z } from 'zod';

export const ssoInitiateQuerySchema = z.object({
    redirect_uri: z.string().url(),
}).passthrough(); // extra opaque query params are forwarded to resolveAuthContext — see initiate.controller.js
