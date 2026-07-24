import crypto from 'crypto';
import { generateSecret, generateURI, verify as verifyTotp } from 'otplib';
import { getState } from '../config/state.js';
import { IdpError } from '../errors/idp-error.js';
import { IDENTITY_STATUS } from '../config/constants.js';
import { verifyPassword } from '../utils/password.js';
import { hashOpaqueToken, verifyMfaChallengeToken as verifyMfaChallengeTokenJwt } from '../signing/token.service.js';
import { auditLog } from '../hooks/index.js';
import { issueSession, setSessionCookies, resolveClaims } from '../password-auth/controllers.js';
import { enforceRateLimit } from '../rate-limit/enforce.js';

// otplib v13's functional API takes `strategy` (default 'totp', so this is
// actually redundant but kept for clarity) and `epochTolerance` — a seconds-
// based clock-skew allowance, NOT the old v12 `window` (steps) option. 30s
// covers one period either side of the default 30s TOTP step, matching the
// intended "current ± 1 step" tolerance without depending on step size.
const TOTP_OPTIONS = { strategy: 'totp', epochTolerance: 30 };

function generateRecoveryCode() {
    const part = () => crypto.randomBytes(3).toString('hex').toUpperCase();
    return `${part()}-${part()}`;
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
        const user = await state.storage.userRepository.findById(req.auth.userId, { select: '+mfaTempSecret mfaEnabled email' });
        if (!user) throw new IdpError({ code: 'USER_NOT_FOUND', httpStatus: 404, message: 'User not found' });
        if (user.mfaEnabled) throw new IdpError({ code: 'MFA_ALREADY_ENABLED', httpStatus: 400, message: 'MFA is already enabled on this account' });

        const secret = generateSecret();
        const otpauthUrl = generateURI({ secret, label: user.email, issuer: state.config.mfa.issuerLabel, strategy: 'totp' });

        await state.storage.userRepository.updateById(req.auth.userId, { mfaTempSecret: secret });
        await auditLog(state.logger, state.hooks, 'MFA_SETUP_INITIATED', { userId: req.auth.userId });

        res.json({ secret, otpauthUrl });
    } catch (err) {
        next(err);
    }
}

export async function confirmMfaHandler(req, res, next) {
    try {
        const state = getState();
        const { code } = req.body;
        const user = await state.storage.userRepository.findById(req.auth.userId, { select: '+mfaTempSecret mfaEnabled' });
        if (!user) throw new IdpError({ code: 'USER_NOT_FOUND', httpStatus: 404, message: 'User not found' });
        if (user.mfaEnabled) throw new IdpError({ code: 'MFA_ALREADY_ENABLED', httpStatus: 400, message: 'MFA is already enabled on this account' });
        if (!user.mfaTempSecret) throw new IdpError({ code: 'MFA_SETUP_REQUIRED', httpStatus: 400, message: 'MFA setup not initiated — call setupMfaHandler first' });

        const { valid } = await verifyTotp({ token: code, secret: user.mfaTempSecret, ...TOTP_OPTIONS });
        if (!valid) throw new IdpError({ code: 'INVALID_MFA_CODE', httpStatus: 400, message: 'Invalid TOTP code' });

        const rawCodes = Array.from({ length: state.config.mfa.recoveryCodeCount }, generateRecoveryCode);
        const codeHashes = rawCodes.map((c) => hashOpaqueToken(state, c));

        await state.storage.userRepository.updateById(req.auth.userId, {
            mfaEnabled: true,
            mfaSecret: user.mfaTempSecret,
            mfaTempSecret: null,
            mfaRecoveryCodes: codeHashes.map((codeHash) => ({ codeHash, usedAt: null })),
        });

        await auditLog(state.logger, state.hooks, 'MFA_ENABLED', { userId: req.auth.userId });
        res.json({ mfaEnabled: true, recoveryCodes: rawCodes }); // shown once — caller must save these
    } catch (err) {
        next(err);
    }
}

export async function disableMfaHandler(req, res, next) {
    try {
        const state = getState();
        const { password, code } = req.body;
        const user = await state.storage.userRepository.findById(req.auth.userId, { select: '+passwordHash +mfaSecret mfaEnabled' });
        if (!user) throw new IdpError({ code: 'USER_NOT_FOUND', httpStatus: 404, message: 'User not found' });
        if (!user.mfaEnabled) throw new IdpError({ code: 'MFA_NOT_ENABLED', httpStatus: 400, message: 'MFA is not enabled on this account' });

        if (!(await verifyPassword(password, user.passwordHash))) {
            throw new IdpError({ code: 'CURRENT_PASSWORD_INCORRECT', httpStatus: 400, message: 'Incorrect password' });
        }
        const { valid } = await verifyTotp({ token: code, secret: user.mfaSecret, ...TOTP_OPTIONS });
        if (!valid) throw new IdpError({ code: 'INVALID_MFA_CODE', httpStatus: 400, message: 'Invalid TOTP code' });

        await state.storage.userRepository.updateById(req.auth.userId, { mfaEnabled: false, mfaSecret: null, mfaTempSecret: null, mfaRecoveryCodes: [] });
        await auditLog(state.logger, state.hooks, 'MFA_DISABLED', { userId: req.auth.userId });
        res.json({ mfaEnabled: false });
    } catch (err) {
        next(err);
    }
}

export async function regenerateRecoveryCodesHandler(req, res, next) {
    try {
        const state = getState();
        const { password } = req.body;
        const user = await state.storage.userRepository.findById(req.auth.userId, { select: '+passwordHash mfaEnabled' });
        if (!user) throw new IdpError({ code: 'USER_NOT_FOUND', httpStatus: 404, message: 'User not found' });
        if (!user.mfaEnabled) throw new IdpError({ code: 'MFA_NOT_ENABLED', httpStatus: 400, message: 'MFA is not enabled on this account' });
        if (!(await verifyPassword(password, user.passwordHash))) {
            throw new IdpError({ code: 'CURRENT_PASSWORD_INCORRECT', httpStatus: 400, message: 'Incorrect password' });
        }

        const rawCodes = Array.from({ length: state.config.mfa.recoveryCodeCount }, generateRecoveryCode);
        const codeHashes = rawCodes.map((c) => hashOpaqueToken(state, c));
        await state.storage.userRepository.updateById(req.auth.userId, { mfaRecoveryCodes: codeHashes.map((codeHash) => ({ codeHash, usedAt: null })) });

        await auditLog(state.logger, state.hooks, 'MFA_RECOVERY_CODES_REGENERATED', { userId: req.auth.userId });
        res.json({ recoveryCodes: rawCodes });
    } catch (err) {
        next(err);
    }
}

/** Completes login after `loginHandler` returned `{ mfaRequired: true }`. Accepts a TOTP code or an unused recovery code. */
export async function verifyMfaChallengeHandler(req, res, next) {
    try {
        const state = getState();
        const { mfaChallengeToken, code } = req.body;

        await enforceRateLimit(state, `mfa-challenge:ip:${req.ip}`, state.config.rateLimiting.mfaChallenge);

        let claimsFromChallenge;
        try {
            claimsFromChallenge = verifyMfaChallengeTokenJwt(state, mfaChallengeToken);
        } catch {
            throw new IdpError({ code: 'INVALID_MFA_CHALLENGE_TOKEN', httpStatus: 401, message: 'Invalid or expired MFA challenge token' });
        }

        const userId = claimsFromChallenge.sub;
        const user = await state.storage.userRepository.findById(userId, { select: '+mfaSecret +mfaRecoveryCodes' });
        if (!user || user.status !== IDENTITY_STATUS.ACTIVE) throw new IdpError({ code: 'USER_NOT_ACTIVE', httpStatus: 403, message: 'User account is not active' });
        if (!user.mfaEnabled) throw new IdpError({ code: 'INVALID_MFA_CHALLENGE_TOKEN', httpStatus: 401, message: 'Invalid or expired MFA challenge token' });

        let verified = false;
        let usedRecoveryCodeIdx = -1;

        const { valid: totpValid } = await verifyTotp({ token: code, secret: user.mfaSecret, ...TOTP_OPTIONS });
        if (totpValid) {
            verified = true;
        } else {
            const codeHash = hashOpaqueToken(state, code);
            const codeHashBuf = Buffer.from(codeHash, 'hex');
            usedRecoveryCodeIdx = (user.mfaRecoveryCodes || []).findIndex((rc) => {
                if (rc.usedAt) return false;
                const stored = Buffer.from(rc.codeHash || '', 'hex');
                return stored.length === codeHashBuf.length && crypto.timingSafeEqual(stored, codeHashBuf);
            });
            if (usedRecoveryCodeIdx >= 0) verified = true;
        }

        if (!verified) {
            await state.storage.userRepository.incrementFailedLoginAttempts(userId);
            throw new IdpError({ code: 'INVALID_MFA_CODE', httpStatus: 400, message: 'Invalid MFA code' });
        }

        if (usedRecoveryCodeIdx >= 0) {
            await state.storage.userRepository.updateById(userId, { [`mfaRecoveryCodes.${usedRecoveryCodeIdx}.usedAt`]: new Date() });
        }

        const claims = await resolveClaims(state, user, { isNewUser: false, method: 'mfa' });
        const session = await issueSession(state, { user, claims, req });

        await auditLog(state.logger, state.hooks, 'MFA_VERIFIED', { userId });

        setSessionCookies(res, state, session);
        res.json({
            accessToken: session.accessToken.token,
            accessTokenExpiresAt: session.accessToken.expiresAt,
            refreshToken: session.refreshTokenValue,
            refreshTokenExpiresAt: session.refreshExpiresAt,
            userId,
        });
    } catch (err) {
        next(err);
    }
}
