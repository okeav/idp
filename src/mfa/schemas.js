import { z } from 'zod';

export const confirmMfaSchema = z.object({ code: z.string().min(6).max(10) }).strict();
export const disableMfaSchema = z.object({ password: z.string().min(1), code: z.string().min(6).max(10) }).strict();
export const regenerateRecoveryCodesSchema = z.object({ password: z.string().min(1) }).strict();
export const verifyMfaChallengeSchema = z.object({
    mfaChallengeToken: z.string().min(1),
    code: z.string().min(6).max(10),
}).strict();
