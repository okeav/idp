import crypto from 'crypto';
import { getState } from '../config/state.js';
import { IdpError } from '../errors/idp-error.js';
import { IDENTITY_STATUS, COOKIE_NAMES, CACHE_KEY_PREFIXES } from '../config/constants.js';
import { issueAccessToken, hashOpaqueToken, generateOpaqueToken } from '../signing/token.service.js';
import { hashPassword, verifyPassword, compareDummyPassword } from '../utils/password.js';
import { buildDeviceFingerprint, detectAndNotifyNewDevice } from '../utils/device-fingerprint.js';
import { auditLog, safeInvokeHook } from '../hooks/index.js';
import { enforceRateLimit } from '../rate-limit/enforce.js';

function refreshTokenExpiresAt(state) {
    return new Date(Date.now() + state.config.ttls.refreshToken * 1000);
}

function cookieOptions(state) {
    const c = state.config.cookies || {};
    return {
        httpOnly: true,
        secure: c.secure ?? process.env.NODE_ENV !== 'development',
        sameSite: c.sameSite || 'lax',
        path: '/',
        ...(c.domain ? { domain: c.domain } : {}),
    };
}

async function resolveClaims(state, user, ctx) {
    const hook = state.hooks?.resolveAuthContext;
    if (typeof hook !== 'function') return {};
    const result = await hook(user, ctx);
    return result?.claims ?? {};
}

/** Builds and persists one full login session (access + refresh token pair) — shared by login, MFA-verify-challenge, and SSO callback. */
async function issueSession(state, { user, claims, req }) {
    const wasFirstLogin = !user.lastLoginAt;
    const deviceInfo = req.headers['user-agent'] || '';
    const deviceFingerprint = buildDeviceFingerprint(deviceInfo);

    const accessToken = await issueAccessToken(state, { sub: String(user.id), email: user.email, claims });
    const refreshTokenValue = generateOpaqueToken();
    const refreshTokenHash = hashOpaqueToken(state, refreshTokenValue);
    const expiresAt = refreshTokenExpiresAt(state);

    await state.storage.sessionRepository.createSessionForLogin({
        accessTokenAudit: { user: user.id, tokenHash: hashOpaqueToken(state, accessToken.token), expiresAt: accessToken.expiresAt, kid: accessToken.kid, jti: accessToken.jti, ipAddress: req.ip, deviceInfo },
        session: {
            user: user.id,
            tokenHash: refreshTokenHash,
            expiresAt,
            kid: accessToken.kid,
            // Shared correlation key: the session's jti equals the paired
            // access token's jti, so a revocation-cache write keyed by this
            // jti is checked by authContextMiddleware against the presented
            // access token without a second lookup.
            jti: accessToken.jti,
            ipAddress: req.ip,
            deviceInfo,
            deviceFingerprint,
            claims,
        },
        userId: user.id,
        lastLoginAt: new Date(),
    });

    detectAndNotifyNewDevice({ sessionRepository: state.storage.sessionRepository, hooks: state.hooks, logger: state.logger, req, user, wasFirstLogin }).catch((err) => {
        state.logger?.warn?.({ err }, 'New-device detection failed (non-fatal)');
    });

    return { accessToken, refreshTokenValue, refreshExpiresAt: expiresAt };
}

function setSessionCookies(res, state, { accessToken, refreshTokenValue, refreshExpiresAt }) {
    const opts = cookieOptions(state);
    res.cookie(COOKIE_NAMES.ACCESS_TOKEN, accessToken.token, { ...opts, expires: accessToken.expiresAt });
    res.cookie(COOKIE_NAMES.REFRESH_TOKEN, refreshTokenValue, { ...opts, expires: refreshExpiresAt });
}

// ── Register ────────────────────────────────────────────────────────────────

export async function registerHandler(req, res, next) {
    try {
        const state = getState();
        const { email, password, firstName, lastName, metadata } = req.body;

        const existing = await state.storage.userRepository.findByEmail(email);
        if (existing) {
            // Spend the same wall-clock as the create path so timing doesn't leak whether the email was new.
            await compareDummyPassword(password);
            return res.status(201).json({ status: 'ok' });
        }

        const passwordHash = await hashPassword(password, state.config.security.bcryptRounds);
        const user = await state.storage.userRepository.create({
            email,
            passwordHash,
            status: IDENTITY_STATUS.PENDING_VERIFICATION,
            profile: { firstName, lastName },
            metadata: metadata || {},
        });

        const { token: verificationToken, verificationCode } = await createEmailVerificationToken(state, user.id);

        await auditLog(state.logger, state.hooks, 'REGISTERED', { userId: String(user.id), email });
        await safeInvokeHook(state.logger, state.hooks, 'onVerificationEmailRequested', { email, firstName, lastName, verificationToken, verificationCode });

        res.status(201).json({ status: 'ok' });
    } catch (err) {
        next(err);
    }
}

async function createEmailVerificationToken(state, userId) {
    const token = generateOpaqueToken(32);
    const tokenHash = hashOpaqueToken(state, token);
    const verificationCode = crypto.randomInt(100000, 1000000).toString();
    await state.storage.verificationTokenRepository.create('email_verification', {
        user: userId,
        tokenHash,
        verificationCode,
        expiresAt: new Date(Date.now() + state.config.ttls.emailVerification * 1000),
    });
    return { token, verificationCode };
}

export async function verifyEmailHandler(req, res, next) {
    try {
        const state = getState();
        const { email, token, code } = req.body;

        const user = await state.storage.userRepository.findByEmail(email);
        if (!user) throw new IdpError({ code: 'USER_NOT_FOUND', httpStatus: 404, message: 'User not found' });

        if (user.status !== IDENTITY_STATUS.PENDING_VERIFICATION) {
            return res.json({ status: 'ok' }); // idempotent — already verified
        }

        const record = token
            ? await state.storage.verificationTokenRepository.consumeByHash('email_verification', hashOpaqueToken(state, token), user.id)
            : await state.storage.verificationTokenRepository.consumeByCode('email_verification', code, user.id);

        if (!record) throw new IdpError({ code: 'INVALID_OR_EXPIRED_TOKEN', httpStatus: 400, message: 'Invalid or expired verification token' });

        await state.storage.userRepository.updateById(user.id, { status: IDENTITY_STATUS.ACTIVE, failedLoginAttempts: 0, lockUntil: null });
        await state.storage.verificationTokenRepository.deleteAllForUser('email_verification', user.id);

        await auditLog(state.logger, state.hooks, 'EMAIL_VERIFIED', { userId: String(user.id), email });

        res.json({ status: 'ok', userId: String(user.id), email: user.email });
    } catch (err) {
        next(err);
    }
}

export async function resendVerificationEmailHandler(req, res, next) {
    try {
        const state = getState();
        const { email } = req.body;

        const user = await state.storage.userRepository.findByEmail(email);
        if (!user) return res.json({ status: 'ok' }); // enumeration-safe

        if (user.status !== IDENTITY_STATUS.PENDING_VERIFICATION) {
            throw new IdpError({ code: 'EMAIL_ALREADY_VERIFIED', httpStatus: 400, message: 'Email is already verified' });
        }

        await state.storage.verificationTokenRepository.deleteAllForUser('email_verification', user.id);
        const { token, verificationCode } = await createEmailVerificationToken(state, user.id);

        await auditLog(state.logger, state.hooks, 'VERIFICATION_TOKEN_REGENERATED', { userId: String(user.id) });
        await safeInvokeHook(state.logger, state.hooks, 'onVerificationEmailRequested', {
            email, firstName: user.profile?.firstName, lastName: user.profile?.lastName, verificationToken: token, verificationCode,
        });

        res.json({ status: 'ok' });
    } catch (err) {
        next(err);
    }
}

// ── Login ────────────────────────────────────────────────────────────────

export async function loginHandler(req, res, next) {
    try {
        const state = getState();
        const { email, password } = req.body;

        await enforceRateLimit(state, `login:ip:${req.ip}`, state.config.rateLimiting.login);
        await enforceRateLimit(state, `login:email:${state.normalizeEmail(email)}`, state.config.rateLimiting.loginByEmail);

        let user = await state.storage.userRepository.findByEmail(email, { select: '+passwordHash' });

        if (user && user.status === IDENTITY_STATUS.LOCKED && user.lockUntil && user.lockUntil <= new Date()) {
            await state.storage.userRepository.updateById(user.id, { failedLoginAttempts: 0, lockUntil: null, status: IDENTITY_STATUS.ACTIVE });
            user.status = IDENTITY_STATUS.ACTIVE;
            user.failedLoginAttempts = 0;
            user.lockUntil = null;
        }

        const passwordValid = user ? await verifyPassword(password, user.passwordHash) : (await compareDummyPassword(password), false);

        if (!user || !passwordValid) {
            if (user && user.status === IDENTITY_STATUS.ACTIVE) {
                await handleFailedLogin(state, user);
            }
            throw new IdpError({ code: 'INVALID_CREDENTIALS', httpStatus: 401, message: 'Invalid email or password' });
        }

        assertUsableStatus(user);

        if (user.mfaEnabled) {
            const { issueMfaChallengeToken } = await import('../signing/token.service.js');
            const challengeToken = await issueMfaChallengeToken(state, user.id);
            return res.json({ mfaRequired: true, mfaChallengeToken: challengeToken, expiresIn: state.config.ttls.mfaChallenge });
        }

        const claims = await resolveClaims(state, user, { isNewUser: false, method: 'password' });
        const session = await issueSession(state, { user, claims, req });

        await auditLog(state.logger, state.hooks, 'LOGIN', { userId: String(user.id), email });

        setSessionCookies(res, state, session);
        res.json({
            accessToken: session.accessToken.token,
            accessTokenExpiresAt: session.accessToken.expiresAt,
            refreshToken: session.refreshTokenValue,
            refreshTokenExpiresAt: session.refreshExpiresAt,
            userId: String(user.id),
        });
    } catch (err) {
        next(err);
    }
}

async function handleFailedLogin(state, user) {
    const updated = await state.storage.userRepository.incrementFailedLoginAttempts(user.id);
    const failedAttempts = updated?.failedLoginAttempts ?? (user.failedLoginAttempts ?? 0) + 1;
    if (failedAttempts >= state.config.security.maxFailedLoginAttempts) {
        const unlocksAt = new Date(Date.now() + state.config.security.accountLockDurationMs);
        await state.storage.userRepository.updateById(user.id, { lockUntil: unlocksAt, status: IDENTITY_STATUS.LOCKED });
        await auditLog(state.logger, state.hooks, 'ACCOUNT_LOCKED', { userId: String(user.id), failedAttempts });
        await safeInvokeHook(state.logger, state.hooks, 'onSuspiciousActivityDetected', {
            userId: String(user.id), email: user.email, firstName: user.profile?.firstName || '', lastName: user.profile?.lastName || '',
            locale: user.profile?.locale || 'en', when: new Date().toISOString(), failedAttempts, unlocksAt: unlocksAt.toISOString(),
        });
    }
}

function assertUsableStatus(user) {
    switch (user.status) {
        case IDENTITY_STATUS.LOCKED:
            throw new IdpError({ code: 'ACCOUNT_LOCKED', httpStatus: 423, message: 'Account is locked due to multiple failed login attempts' });
        case IDENTITY_STATUS.SUSPENDED:
        case IDENTITY_STATUS.DISABLED:
            throw new IdpError({ code: 'ACCOUNT_SUSPENDED', httpStatus: 403, message: 'Account is suspended' });
        case IDENTITY_STATUS.PENDING_VERIFICATION:
        case IDENTITY_STATUS.INVITED:
            throw new IdpError({ code: 'PENDING_VERIFICATION', httpStatus: 403, message: 'Account is pending verification' });
        case IDENTITY_STATUS.DELETED:
            throw new IdpError({ code: 'INVALID_CREDENTIALS', httpStatus: 401, message: 'Invalid email or password' });
        case IDENTITY_STATUS.ACTIVE:
            return;
        default:
            throw new IdpError({ code: 'USER_NOT_ACTIVE', httpStatus: 403, message: 'User account is not active' });
    }
}

// ── Refresh / logout ────────────────────────────────────────────────────────

export async function refreshTokenHandler(req, res, next) {
    try {
        const state = getState();
        await enforceRateLimit(state, `refresh:ip:${req.ip}`, state.config.rateLimiting.refreshToken);

        const refreshTokenValue = req.cookies?.[COOKIE_NAMES.REFRESH_TOKEN] || req.body?.refreshToken;
        if (!refreshTokenValue) throw new IdpError({ code: 'REFRESH_TOKEN_REQUIRED', httpStatus: 400, message: 'Refresh token is required' });

        const tokenHash = hashOpaqueToken(state, refreshTokenValue);
        const existing = await state.storage.sessionRepository.revokeByRefreshTokenHash(tokenHash);
        if (!existing) throw new IdpError({ code: 'INVALID_REFRESH_TOKEN', httpStatus: 401, message: 'Invalid or expired refresh token' });

        const user = await state.storage.userRepository.findById(existing.user, { select: 'email status' });
        if (!user || user.status !== IDENTITY_STATUS.ACTIVE) throw new IdpError({ code: 'USER_NOT_ACTIVE', httpStatus: 403, message: 'User account is not active' });

        const accessToken = await issueAccessToken(state, { sub: String(user.id), email: user.email, claims: existing.claims || {} });
        const newRefreshTokenValue = generateOpaqueToken();
        const newRefreshTokenHash = hashOpaqueToken(state, newRefreshTokenValue);
        const refreshExpiresAt = refreshTokenExpiresAt(state);
        const deviceInfo = req.headers['user-agent'] || existing.deviceInfo || '';

        await state.storage.sessionRepository.createSession({
            user: user.id,
            tokenHash: newRefreshTokenHash,
            expiresAt: refreshExpiresAt,
            kid: accessToken.kid,
            jti: accessToken.jti,
            ipAddress: req.ip,
            deviceInfo,
            deviceFingerprint: buildDeviceFingerprint(deviceInfo),
            claims: existing.claims || {},
        });

        await state.cache.set(`${CACHE_KEY_PREFIXES.REVOKED_REFRESH_TOKEN}:${existing.jti}`, '1', state.config.ttls.revocationCache);

        await auditLog(state.logger, state.hooks, 'TOKEN_REFRESHED', { userId: String(user.id) });

        setSessionCookies(res, state, { accessToken, refreshTokenValue: newRefreshTokenValue, refreshExpiresAt });
        res.json({ accessToken: accessToken.token, accessTokenExpiresAt: accessToken.expiresAt, refreshToken: newRefreshTokenValue, refreshTokenExpiresAt: refreshExpiresAt });
    } catch (err) {
        next(err);
    }
}

export async function logoutHandler(req, res, next) {
    try {
        const state = getState();
        const refreshTokenValue = req.body?.refreshToken || req.cookies?.[COOKIE_NAMES.REFRESH_TOKEN];
        if (!refreshTokenValue) throw new IdpError({ code: 'REFRESH_TOKEN_REQUIRED', httpStatus: 400, message: 'Refresh token is required to log out' });

        const tokenHash = hashOpaqueToken(state, refreshTokenValue);
        const existing = await state.storage.sessionRepository.revokeByRefreshTokenHash(tokenHash, { onlyIfActive: false });
        if (existing?.jti) {
            await state.cache.set(`${CACHE_KEY_PREFIXES.REVOKED_REFRESH_TOKEN}:${existing.jti}`, '1', state.config.ttls.revocationCache);
        }

        await auditLog(state.logger, state.hooks, 'LOGOUT', { userId: String(existing?.user ?? req.auth?.userId ?? 'unknown') });
        res.clearCookie(COOKIE_NAMES.ACCESS_TOKEN);
        res.clearCookie(COOKIE_NAMES.REFRESH_TOKEN);
        res.json({ status: 'ok' });
    } catch (err) {
        next(err);
    }
}

export async function logoutAllHandler(req, res, next) {
    try {
        const state = getState();
        if (!req.auth?.userId) throw new IdpError({ code: 'UNAUTHENTICATED', httpStatus: 401, message: 'Authentication required' });

        await state.storage.sessionRepository.revokeAllForUser(req.auth.userId);
        await auditLog(state.logger, state.hooks, 'LOGOUT_ALL', { userId: req.auth.userId });
        res.json({ status: 'ok' });
    } catch (err) {
        next(err);
    }
}

// ── Password ─────────────────────────────────────────────────────────────

export async function forgotPasswordHandler(req, res, next) {
    try {
        const state = getState();
        const { email } = req.body;

        await enforceRateLimit(state, `password-reset:ip:${req.ip}`, state.config.rateLimiting.passwordReset);

        const user = await state.storage.userRepository.findByEmail(email);
        if (!user) return res.json({ status: 'ok' }); // enumeration-safe

        const resetToken = generateOpaqueToken(32);
        await state.storage.verificationTokenRepository.create('password_reset', {
            user: user.id,
            tokenHash: hashOpaqueToken(state, resetToken),
            expiresAt: new Date(Date.now() + state.config.ttls.passwordReset * 1000),
        });

        await safeInvokeHook(state.logger, state.hooks, 'onPasswordResetRequested', {
            email, resetToken, firstName: user.profile?.firstName, lastName: user.profile?.lastName,
        });

        res.json({ status: 'ok' });
    } catch (err) {
        next(err);
    }
}

export async function resetPasswordHandler(req, res, next) {
    try {
        const state = getState();
        const { email, token, newPassword } = req.body;

        const user = await state.storage.userRepository.findByEmail(email);
        if (!user) throw new IdpError({ code: 'INVALID_OR_EXPIRED_TOKEN', httpStatus: 400, message: 'Invalid or expired token' });

        const record = await state.storage.verificationTokenRepository.consumeByHash('password_reset', hashOpaqueToken(state, token), user.id);
        if (!record) throw new IdpError({ code: 'INVALID_OR_EXPIRED_TOKEN', httpStatus: 400, message: 'Invalid or expired token' });

        const passwordHash = await hashPassword(newPassword, state.config.security.bcryptRounds);
        await state.storage.userRepository.updateById(record.user, { passwordHash, passwordChangedAt: new Date() });
        await state.storage.sessionRepository.revokeAllForUser(record.user);

        await auditLog(state.logger, state.hooks, 'PASSWORD_RESET', { userId: String(record.user) });
        res.json({ status: 'ok' });
    } catch (err) {
        next(err);
    }
}

export async function changePasswordHandler(req, res, next) {
    try {
        const state = getState();
        const userId = req.auth?.userId;
        if (!userId) throw new IdpError({ code: 'UNAUTHENTICATED', httpStatus: 401, message: 'Authentication required' });

        const { currentPassword, newPassword } = req.body;
        const user = await state.storage.userRepository.findById(userId, { select: '+passwordHash' });
        if (!user) throw new IdpError({ code: 'USER_NOT_FOUND', httpStatus: 404, message: 'User not found' });

        const valid = await verifyPassword(currentPassword, user.passwordHash);
        if (!valid) throw new IdpError({ code: 'CURRENT_PASSWORD_INCORRECT', httpStatus: 400, message: 'Current password is incorrect' });

        const passwordHash = await hashPassword(newPassword, state.config.security.bcryptRounds);
        await state.storage.userRepository.updateById(userId, { passwordHash, passwordChangedAt: new Date() });
        await state.storage.sessionRepository.revokeAllForUser(userId);

        await auditLog(state.logger, state.hooks, 'PASSWORD_CHANGED', { userId });
        await safeInvokeHook(state.logger, state.hooks, 'onPasswordChanged', {
            userId, email: user.email, firstName: user.profile?.firstName || '', lastName: user.profile?.lastName || '',
            locale: user.profile?.locale || 'en', when: new Date().toISOString(), deviceInfo: req.headers['user-agent'] || '', ipAddress: req.ip || '',
        });

        res.json({ status: 'ok' });
    } catch (err) {
        next(err);
    }
}

// ── Self-service identity ("me") ────────────────────────────────────────────

export async function getMeHandler(req, res, next) {
    try {
        const state = getState();
        if (!req.auth?.userId) throw new IdpError({ code: 'UNAUTHENTICATED', httpStatus: 401, message: 'Authentication required' });

        const user = await state.storage.userRepository.findById(req.auth.userId, { select: 'email status mfaEnabled profile createdAt updatedAt' });
        if (!user) throw new IdpError({ code: 'USER_NOT_FOUND', httpStatus: 404, message: 'User not found' });

        res.json({
            userId: String(user.id),
            email: user.email,
            emailVerified: user.status !== IDENTITY_STATUS.PENDING_VERIFICATION,
            isActive: user.status === IDENTITY_STATUS.ACTIVE,
            status: user.status,
            mfaEnabled: user.mfaEnabled,
            profile: user.profile,
            createdAt: user.createdAt,
            updatedAt: user.updatedAt,
        });
    } catch (err) {
        next(err);
    }
}

export async function updateMeHandler(req, res, next) {
    try {
        const state = getState();
        if (!req.auth?.userId) throw new IdpError({ code: 'UNAUTHENTICATED', httpStatus: 401, message: 'Authentication required' });

        const patch = {};
        for (const key of ['firstName', 'lastName', 'displayName', 'avatarUrl', 'locale', 'zoneinfo']) {
            if (req.body[key] !== undefined) patch[`profile.${key}`] = req.body[key];
        }

        const user = await state.storage.userRepository.updateById(req.auth.userId, patch);
        if (!user) throw new IdpError({ code: 'USER_NOT_FOUND', httpStatus: 404, message: 'User not found' });

        await auditLog(state.logger, state.hooks, 'PROFILE_UPDATED', { userId: req.auth.userId });
        res.json({ userId: String(user.id), profile: user.profile, updatedAt: user.updatedAt });
    } catch (err) {
        next(err);
    }
}

export async function deleteMeHandler(req, res, next) {
    try {
        const state = getState();
        if (!req.auth?.userId) throw new IdpError({ code: 'UNAUTHENTICATED', httpStatus: 401, message: 'Authentication required' });

        const user = await state.storage.userRepository.updateById(req.auth.userId, { status: IDENTITY_STATUS.DELETED });
        if (!user) throw new IdpError({ code: 'USER_NOT_FOUND', httpStatus: 404, message: 'User not found' });

        await state.storage.sessionRepository.revokeAllForUser(req.auth.userId);
        await auditLog(state.logger, state.hooks, 'ACCOUNT_DELETED', { userId: req.auth.userId });
        res.json({ status: 'ok' });
    } catch (err) {
        next(err);
    }
}

export async function listSessionsHandler(req, res, next) {
    try {
        const state = getState();
        if (!req.auth?.userId) throw new IdpError({ code: 'UNAUTHENTICATED', httpStatus: 401, message: 'Authentication required' });

        const sessions = await state.storage.sessionRepository.listActiveForUser(req.auth.userId);
        res.json(sessions.map((s) => ({ id: s.id, ipAddress: s.ipAddress, deviceInfo: s.deviceInfo, createdAt: s.createdAt, expiresAt: s.expiresAt })));
    } catch (err) {
        next(err);
    }
}

export async function revokeSessionHandler(req, res, next) {
    try {
        const state = getState();
        if (!req.auth?.userId) throw new IdpError({ code: 'UNAUTHENTICATED', httpStatus: 401, message: 'Authentication required' });

        const session = await state.storage.sessionRepository.revokeById(req.params.id, req.auth.userId);
        if (!session) throw new IdpError({ code: 'REFRESH_TOKEN_NOT_FOUND', httpStatus: 404, message: 'Session not found' });

        if (session.jti) await state.cache.set(`${CACHE_KEY_PREFIXES.REVOKED_REFRESH_TOKEN}:${session.jti}`, '1', state.config.ttls.revocationCache);
        await auditLog(state.logger, state.hooks, 'SESSION_REVOKED', { userId: req.auth.userId, sessionId: req.params.id });
        res.json({ status: 'ok' });
    } catch (err) {
        next(err);
    }
}

export async function revokeAllSessionsHandler(req, res, next) {
    try {
        const state = getState();
        if (!req.auth?.userId) throw new IdpError({ code: 'UNAUTHENTICATED', httpStatus: 401, message: 'Authentication required' });

        const result = await state.storage.sessionRepository.revokeAllForUser(req.auth.userId);
        await auditLog(state.logger, state.hooks, 'SESSIONS_REVOKED_ALL', { userId: req.auth.userId, revokedCount: result.revokedCount });
        res.json({ status: 'ok', revokedCount: result.revokedCount });
    } catch (err) {
        next(err);
    }
}

export { issueSession, setSessionCookies, resolveClaims, cookieOptions, refreshTokenExpiresAt, assertUsableStatus };
