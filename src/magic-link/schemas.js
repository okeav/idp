import { z } from 'zod';
import { MAX_EMAIL_LENGTH } from '../config/constants.js';

export const requestMagicLinkSchema = z.object({
    email: z.string().trim().toLowerCase().email('Must be a valid email address').max(MAX_EMAIL_LENGTH),
}).strict();

export const verifyMagicLinkSchema = z.object({
    token: z.string().min(1),
}).strict();
