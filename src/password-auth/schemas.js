import { z } from 'zod';
import { PASSWORD_POLICY_DEFAULTS, NAME_REGEX, MAX_EMAIL_LENGTH, MAX_NAME_LENGTH } from '../config/constants.js';

const email = () => z.string().trim().toLowerCase().email('Must be a valid email address').max(MAX_EMAIL_LENGTH);
const name = () => z.string().trim().max(MAX_NAME_LENGTH).regex(NAME_REGEX, 'Contains invalid characters');
const password = () =>
    z.string()
        .min(PASSWORD_POLICY_DEFAULTS.minLength, `Password must be at least ${PASSWORD_POLICY_DEFAULTS.minLength} characters`)
        .max(PASSWORD_POLICY_DEFAULTS.maxLength)
        .regex(PASSWORD_POLICY_DEFAULTS.uppercase, 'Password must contain at least one uppercase letter')
        .regex(PASSWORD_POLICY_DEFAULTS.lowercase, 'Password must contain at least one lowercase letter')
        .regex(PASSWORD_POLICY_DEFAULTS.number, 'Password must contain at least one number')
        .regex(PASSWORD_POLICY_DEFAULTS.special, 'Password must contain at least one special character');

export const registerSchema = z.object({
    email: email(),
    password: password(),
    firstName: name().optional(),
    lastName: name().optional(),
    // Opaque bag the consumer may want persisted on the user record —
    // never interpreted by this package.
    metadata: z.record(z.string(), z.unknown()).optional(),
}).strict();

export const verifyEmailSchema = z.object({
    email: email(),
    token: z.string().optional(),
    code: z.string().optional(),
}).strict().refine((v) => v.token || v.code, { message: 'Either token or code is required' });

export const resendVerificationSchema = z.object({ email: email() }).strict();

export const loginSchema = z.object({ email: email(), password: z.string().min(1) }).strict();

export const forgotPasswordSchema = z.object({ email: email() }).strict();

export const resetPasswordSchema = z.object({
    email: email(),
    token: z.string().min(1),
    newPassword: password(),
}).strict();

export const changePasswordSchema = z.object({
    currentPassword: z.string().min(1),
    newPassword: password(),
}).strict();

export const logoutSchema = z.object({ refreshToken: z.string().min(1) }).strict();

export const updateProfileSchema = z.object({
    firstName: name().optional(),
    lastName: name().optional(),
    displayName: z.string().trim().max(150).optional(),
    avatarUrl: z.string().url().optional(),
    locale: z.string().max(16).optional(),
    zoneinfo: z.string().max(64).optional(),
}).strict();
