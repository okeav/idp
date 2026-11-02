import { z } from 'zod';
import { PASSWORD_POLICY_DEFAULTS, NAME_REGEX, MAX_EMAIL_LENGTH, MAX_NAME_LENGTH } from '../config/constants.js';

const email = () => z.string().trim().toLowerCase().email('Must be a valid email address').max(MAX_EMAIL_LENGTH);
const name = () => z.string().trim().max(MAX_NAME_LENGTH).regex(NAME_REGEX, 'Contains invalid characters');
// bcrypt only reads the first 72 BYTES of a password: anything after that is silently ignored, so two
// long passwords sharing a 72-byte prefix would both log in. Longer passwords are refused instead
// (72 bytes is 72 ASCII characters, fewer for multi-byte UTF-8).
const BCRYPT_MAX_BYTES = 72;
const password = () =>
    z.string()
        .min(PASSWORD_POLICY_DEFAULTS.minLength, `Password must be at least ${PASSWORD_POLICY_DEFAULTS.minLength} characters`)
        .max(PASSWORD_POLICY_DEFAULTS.maxLength)
        .refine((v) => Buffer.byteLength(v, 'utf8') <= BCRYPT_MAX_BYTES, `Password must be at most ${BCRYPT_MAX_BYTES} bytes`)
        .regex(PASSWORD_POLICY_DEFAULTS.uppercase, 'Password must contain at least one uppercase letter')
        .regex(PASSWORD_POLICY_DEFAULTS.lowercase, 'Password must contain at least one lowercase letter')
        .regex(PASSWORD_POLICY_DEFAULTS.number, 'Password must contain at least one number')
        .regex(PASSWORD_POLICY_DEFAULTS.special, 'Password must contain at least one special character');

export const registerSchema = z.object({
    email: email(),
    password: password(),
    firstName: name().optional(),
    lastName: name().optional(),
    // Opaque bag persisted on the user record — but only when config.registration.acceptMetadata is
    // true (ignored otherwise): it is written by the person registering, so it must never hold
    // anything an app trusts (a role, a tenant, a plan).
    metadata: z.record(z.string(), z.unknown()).optional(),
}).strict();

export const verifyEmailSchema = z.object({
    email: email(),
    token: z.string().optional(),
    code: z.string().optional(),
}).strict().refine((v) => v.token || v.code, { message: 'Either token or code is required' });

export const resendVerificationSchema = z.object({ email: email() }).strict();

export const loginSchema = z.object({ email: email(), password: z.string().min(1).max(1024) }).strict();

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

// refreshToken is optional: browser clients send it as the httpOnly refresh_token cookie instead, which logoutHandler also reads.
export const logoutSchema = z.object({ refreshToken: z.string().min(1).max(512).optional() }).strict().optional();
// Same shape for /refresh: a non-string refreshToken used to reach the token hasher and 500.
export const refreshSchema = logoutSchema;

export const updateProfileSchema = z.object({
    firstName: name().optional(),
    lastName: name().optional(),
    displayName: z.string().trim().max(150).optional(),
    // Released as the ID token's `picture` claim, which relying parties render: https only (never
    // javascript: / data:).
    avatarUrl: z.string().max(2048).refine((v) => { try { return new URL(v).protocol === 'https:'; } catch { return false; } }, 'avatarUrl must be an https URL').optional(),
    locale: z.string().regex(/^[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})*$/, 'locale must be a BCP 47 language tag').max(35).optional(),
    zoneinfo: z.string().regex(/^[A-Za-z0-9_+-/]{1,64}$/, 'zoneinfo must be an IANA time zone name').optional(),
}).strict();
