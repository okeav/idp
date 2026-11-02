import crypto from 'crypto';
import { generateSecret, generateURI, verify as verifyTotp } from 'otplib';
import { getState } from '../config/state.js';
import { assertTrustedOrigin } from '../middleware/csrf.js';
import { IdpError } from '../errors/idp-error.js';
import { isActiveAccount } from '../utils/account-status.js';
import { verifyPassword } from '../utils/password.js';
import { hashOpaqueToken, verifyMfaChallengeToken as verifyMfaChallengeTokenJwt } from '../signing/token.service.js';
import { auditLog } from '../hooks/index.js';
import { issueSession, setSessionCookies, resolveClaims, refreshTokenInBody } from '../password-auth/controllers.js';
import { enforceRateLimit } from '../rate-limit/enforce.js';
import { ipKey } from '../rate-limit/keys.js';
import { sealMfaSecret, openMfaSecret } from './secrets.js';
import { guardMfaAttempt } from './attempt-guard.js';
import { claimTotpStep, consumeRecoveryCode, claimMfaChallenge } from './factor-store.js';
import { revokeOtherUserSessions } from '../utils/session-family.js';

// otplib v13's functional API takes `strategy` (default 'totp', so this is
// actually redundant but kept for clarity) and `epochTolerance` — a seconds-
// based clock-skew allowance, NOT the old v12 `window` (steps) option. 30s
// covers one period either side of the default 30s TOTP step, matching the
// intended "current ± 1 step" tolerance without depending on step size.
const TOTP_OPTIONS = { strategy: 'totp', epochTolerance: 30 };

// otplib v13 throws (TokenLengthError) on anything that isn't exactly 6
// digits — including every recovery code (XXXXXX-XXXXXX). Such a code just
// isn't a valid TOTP; it must fall through to the recovery-code check, not 500.
/** The matched TOTP time step, or null when the code doesn't verify. */
async function totpStep(code, secret) {
    if (!secret || !/^\d{6}$/.test(code)) return null;
    const result = await verifyTotp({ token: code, secret, ...TOTP_OPTIONS });
    return result.valid ? result.timeStep : null;
}

/**
 * True when `code` verifies against `secret` AND its time step hasn't been accepted for this account
 * before. Without the second check a code seen once (shoulder-surfed, logged, replayed from a
 * captured request) works again for the rest of its ±30s window.
 */
async function totpAccepted(state, userId, code, secret) {
    const step = await totpStep(code, secret);
    return step !== null && claimTotpStep(state, userId, step);
}

const isWrongCode = (err) => err?.code === 'INVALID_MFA_CODE';
// For the re-authenticating MFA routes (disable, regenerate codes) a wrong password is a guess too.
const isWrongCodeOrPassword = (err) => isWrongCode(err) || err?.code === 'CURRENT_PASSWORD_INCORRECT';

function invalidCode(message = 'Invalid TOTP code') {
    return new IdpError({ code: 'INVALID_MFA_CODE', httpStatus: 400, message });
}

const INVALID_CHALLENGE = () => new IdpError({ code: 'INVALID_MFA_CHALLENGE_TOKEN', httpStatus: 401, message: 'Invalid or expired MFA challenge token' });

function assertMfaFeatureEnabled(state) {
    if (state.config.mfa.enabled === false) {
        throw new IdpError({ code: 'FEATURE_DISABLED', httpStatus: 404, message: 'MFA is not enabled on this server' });
    }
}

// Crockford base32: no I, L, O, U — nothing to misread when typing a code off paper.
const RECOVERY_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

/**
 * 20 characters of base32 = 100 bits, shown as XXXXX-XXXXX-XXXXX-XXXXX. (0.3.0 used 48 bits: with the
 * database and the HMAC key, every user's codes fell to one offline search.)
 */
function generateRecoveryCode() {
    const chars = Array.from({ length: 20 }, () => RECOVERY_ALPHABET[crypto.randomInt(RECOVERY_ALPHABET.length)]).join('');
    return chars.match(/.{5}/g).join('-');
}

/** Accept a code however it's typed: any case, spaces or dashes, and O/I/L for 0/1. */
const normalizeRecoveryCode = (code) => String(code).toUpperCase().replace(/[\s-]/g, '').replace(/O/g, '0').replace(/[IL]/g, '1');

/** Keyed hash of a recovery code, bound to its user — one guess can't be tested against everyone's codes at once. */
const recoveryCodeHash = (state, userId, code) => hashOpaqueToken(state, `mfa-recovery:${userId}:${normalizeRecoveryCode(code)}`);

function newRecoveryCodes(state, userId) {
    const rawCodes = Array.from({ length: state.config.mfa.recoveryCodeCount }, generateRecoveryCode);
    return { rawCodes, stored: rawCodes.map((c) => ({ codeHash: recoveryCodeHash(state, userId, c), usedAt: null })) };
}

/** Re-authentication for the routes that weaken or re-issue the second factor: the password (when the account has one). */
async function assertPassword(user, password) {
    if (!user.passwordHash) return; // passwordless account (SSO / magic link): the TOTP code is the re-authentication
    if (!(await verifyPassword(password ?? '', user.passwordHash))) {
        throw new IdpError({ code: 'CURRENT_PASSWORD_INCORRECT', httpStatus: 400, message: 'Incorrect password' });
    }
}

/**
 * Verifies an MFA challenge token for completing a login, and that it's still current: a challenge
 * issued before the account's last password change is void (it was earned with the old password).
 * Shared with WebAuthn-as-MFA.
 */
export function verifyChallengeToken(state, mfaChallengeToken) {
    try {
        const claims = verifyMfaChallengeTokenJwt(state, mfaChallengeToken);
        if (!claims.jti) throw INVALID_CHALLENGE();
        return claims;
    } catch {
        throw INVALID_CHALLENGE();
    }
}

export function assertChallengeCurrent(user, challengeClaims) {
    const changedAt = user.passwordChangedAt ? Math.floor(new Date(user.passwordChangedAt).getTime() / 1000) : null;
    if (changedAt !== null && challengeClaims.iat < changedAt) throw INVALID_CHALLENGE();
}

/** Spends the challenge token (one token, one login) — after the factor checked out. */
export async function spendChallenge(state, challengeClaims) {
    if (!(await claimMfaChallenge(state, challengeClaims))) throw INVALID_CHALLENGE();
}

export async function getMfaStatusHandler(req, res, next) {
    try {
        const state = getState();
        const user = await state.storage.userRepository.findById(req.auth.userId, { select: 'mfaEnabled' });
        if (!user) throw new IdpError({ code: 'USER_NOT_FOUND', httpStatus: 404, message: 'User not found' });
        res.json({ mfaEnabled: Boolean(user.mfaEnabled) });
    } catch (err) {
        next(err);
    }
}

/**
 * Returns the raw `otpauth://` URI only — this package does not depend on a
 * QR-code renderer. The consumer renders their own QR code client-side from
 * the URI (e.g. with the `qrcode` npm package, or a frontend QR component).
 */
export async function setupMfaHandler(req, res, next) {
    try {
        const state = getState();
        assertMfaFeatureEnabled(state);
        const user = await state.storage.userRepository.findById(req.auth.userId, { select: '+mfaTempSecret mfaEnabled email' });
        if (!user) throw new IdpError({ code: 'USER_NOT_FOUND', httpStatus: 404, message: 'User not found' });
        if (user.mfaEnabled) throw new IdpError({ code: 'MFA_ALREADY_ENABLED', httpStatus: 400, message: 'MFA is already enabled on this account' });

        const secret = generateSecret();
        const otpauthUrl = generateURI({ secret, label: user.email, issuer: state.config.mfa.issuerLabel, strategy: 'totp' });

        await state.storage.userRepository.updateById(req.auth.userId, { mfaTempSecret: await sealMfaSecret(state, secret, req.auth.userId) });
        await auditLog(state.logger, state.hooks, 'MFA_SETUP_INITIATED', { userId: req.auth.userId });

        res.set('Cache-Control', 'no-store');
        res.json({ secret, otpauthUrl });
    } catch (err) {
        next(err);
    }
}

export async function confirmMfaHandler(req, res, next) {
    try {
        const state = getState();
        assertMfaFeatureEnabled(state);
        const { code } = req.body;
        const userId = req.auth.userId;
        const user = await state.storage.userRepository.findById(userId, { select: '+mfaTempSecret mfaEnabled' });
        if (!user) throw new IdpError({ code: 'USER_NOT_FOUND', httpStatus: 404, message: 'User not found' });
        if (user.mfaEnabled) throw new IdpError({ code: 'MFA_ALREADY_ENABLED', httpStatus: 400, message: 'MFA is already enabled on this account' });
        if (!user.mfaTempSecret) throw new IdpError({ code: 'MFA_SETUP_REQUIRED', httpStatus: 400, message: 'MFA setup not initiated — call setupMfaHandler first' });

        const { secret } = await openMfaSecret(state, user.mfaTempSecret, userId);
        await guardMfaAttempt(state, userId, { method: 'totp-enrolment', isFailure: isWrongCode }, async () => {
            // Claims the step too, so the code that confirmed enrolment can't then complete a login.
            if (!(await totpAccepted(state, userId, code, secret))) throw invalidCode();
        });

        const { rawCodes, stored } = newRecoveryCodes(state, userId);
        await state.storage.userRepository.updateById(userId, {
            mfaEnabled: true,
            // Re-sealed rather than copied: a temp secret written before
            // encryption existed is plain text, and the permanent one never should be.
            mfaSecret: await sealMfaSecret(state, secret, userId),
            mfaTempSecret: null,
            mfaRecoveryCodes: stored,
        });

        // Any other session may predate the account being secured (or be an attacker's): end them, keep this one.
        // With the same watermark as "sign out everywhere", minus this session's family — so a refresh of
        // another session that was already in flight is caught as well.
        const { revokedCount } = await revokeOtherUserSessions(state, userId, { exceptJti: req.auth.tokenMeta?.jti });
        await auditLog(state.logger, state.hooks, 'MFA_ENABLED', { userId: req.auth.userId, revokedOtherSessions: revokedCount });
        res.set('Cache-Control', 'no-store');
        res.json({ mfaEnabled: true, recoveryCodes: rawCodes }); // shown once — caller must save these
    } catch (err) {
        next(err);
    }
}

export async function disableMfaHandler(req, res, next) {
    try {
        const state = getState();
        const { password, code } = req.body;
        const userId = req.auth.userId;
        const user = await state.storage.userRepository.findById(userId, { select: '+passwordHash +mfaSecret mfaEnabled' });
        if (!user) throw new IdpError({ code: 'USER_NOT_FOUND', httpStatus: 404, message: 'User not found' });
        if (!user.mfaEnabled) throw new IdpError({ code: 'MFA_NOT_ENABLED', httpStatus: 400, message: 'MFA is not enabled on this account' });

        // Counted before the password is checked too, so this route is no
        // password oracle, locked or not.
        await guardMfaAttempt(state, userId, { method: 'totp-disable', isFailure: isWrongCodeOrPassword }, async () => {
            await assertPassword(user, password);
            const opened = await openMfaSecret(state, user.mfaSecret, userId);
            if (!(await totpAccepted(state, userId, code, opened?.secret))) throw invalidCode();
        });

        await state.storage.userRepository.updateById(userId, { mfaEnabled: false, mfaSecret: null, mfaTempSecret: null, mfaRecoveryCodes: [], mfaLastTotpStep: null });
        await auditLog(state.logger, state.hooks, 'MFA_DISABLED', { userId: req.auth.userId });
        res.json({ mfaEnabled: false });
    } catch (err) {
        next(err);
    }
}

/** Re-issues the recovery codes. Requires a current TOTP code as well as the password: whoever holds only a session (or only the password) must not mint themselves a fresh set of second factors. */
export async function regenerateRecoveryCodesHandler(req, res, next) {
    try {
        const state = getState();
        const { password, code } = req.body;
        const userId = req.auth.userId;
        const user = await state.storage.userRepository.findById(userId, { select: '+passwordHash +mfaSecret mfaEnabled' });
        if (!user) throw new IdpError({ code: 'USER_NOT_FOUND', httpStatus: 404, message: 'User not found' });
        if (!user.mfaEnabled) throw new IdpError({ code: 'MFA_NOT_ENABLED', httpStatus: 400, message: 'MFA is not enabled on this account' });

        await guardMfaAttempt(state, userId, { method: 'recovery-codes', isFailure: isWrongCodeOrPassword }, async () => {
            await assertPassword(user, password);
            const opened = await openMfaSecret(state, user.mfaSecret, userId);
            if (!(await totpAccepted(state, userId, code, opened?.secret))) throw invalidCode();
        });

        const { rawCodes, stored } = newRecoveryCodes(state, userId);
        await state.storage.userRepository.updateById(userId, { mfaRecoveryCodes: stored });

        await auditLog(state.logger, state.hooks, 'MFA_RECOVERY_CODES_REGENERATED', { userId });
        res.set('Cache-Control', 'no-store');
        res.json({ recoveryCodes: rawCodes });
    } catch (err) {
        next(err);
    }
}

/** Completes login after a first factor returned `{ mfaRequired: true }`. Accepts a TOTP code or an unused recovery code. */
export async function verifyMfaChallengeHandler(req, res, next) {
    try {
        const state = getState();
        assertTrustedOrigin(state, req); // sets session cookies — refuse login CSRF (see middleware/csrf.js)
        const { mfaChallengeToken, code } = req.body;

        await enforceRateLimit(state, `mfa-challenge:ip:${ipKey(req.ip)}`, state.config.rateLimiting.mfaChallenge, { failMode: 'closed' });

        const challenge = verifyChallengeToken(state, mfaChallengeToken);
        const userId = challenge.sub;
        const user = await state.storage.userRepository.findById(userId, { select: '+mfaSecret +mfaRecoveryCodes' });
        if (!isActiveAccount(user)) throw new IdpError({ code: 'USER_NOT_ACTIVE', httpStatus: 403, message: 'User account is not active' });
        if (!user.mfaEnabled) throw INVALID_CHALLENGE();
        assertChallengeCurrent(user, challenge);

        // TOTP and recovery codes share one per-account counter: a guess is a
        // guess whichever kind of code it's aimed at. Each is spent atomically
        // inside the guard, so neither can be used twice — not even by two
        // requests racing with the same code.
        const { opened, method } = await guardMfaAttempt(state, userId, { method: 'totp', isFailure: isWrongCode }, async () => {
            const opened = await openMfaSecret(state, user.mfaSecret, userId);
            if (await totpAccepted(state, userId, code, opened?.secret)) return { opened, method: 'totp' };

            const codeHash = recoveryCodeHash(state, user.id, code);
            if (await consumeRecoveryCode(state, user, codeHash)) return { opened, method: 'recovery-code' };

            throw invalidCode('Invalid MFA code');
        });

        await spendChallenge(state, challenge);

        // Lazy migration: a plain-text secret (or one under a retired key) is
        // re-sealed under the current key on the first successful verify.
        if (opened?.needsUpgrade) await state.storage.userRepository.updateById(userId, { mfaSecret: await sealMfaSecret(state, opened.secret, userId) });

        const claims = await resolveClaims(state, user, { isNewUser: false, method: 'mfa' });
        const session = await issueSession(state, { user, claims, req });

        await auditLog(state.logger, state.hooks, 'MFA_VERIFIED', { userId, method });

        setSessionCookies(res, state, session);
        res.json({
            accessToken: session.accessToken.token,
            accessTokenExpiresAt: session.accessToken.expiresAt,
            ...refreshTokenInBody(state, session.refreshTokenValue),
            refreshTokenExpiresAt: session.refreshExpiresAt,
            userId,
        });
    } catch (err) {
        next(err);
    }
}
