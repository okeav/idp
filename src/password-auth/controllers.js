import crypto from 'crypto';
import { getState } from '../config/state.js';
import { IdpError } from '../errors/idp-error.js';
import { IDENTITY_STATUS, COOKIE_NAMES, CACHE_KEY_PREFIXES, SESSION_KINDS } from '../config/constants.js';
import { sessionKindOf } from '../utils/session-kind.js';
import { issueAccessToken, issueMfaChallengeToken, hashOpaqueToken, generateOpaqueToken } from '../signing/token.service.js';
import { hashPassword, verifyPassword, compareDummyPassword } from '../utils/password.js';
import { buildDeviceFingerprint, notifyNewDevice } from '../utils/device-fingerprint.js';
import { newFamilyId, familyOf, familyEndsAt, cappedExpiry, handleRefreshReuse, revokeAllUserSessions, assertChainNotRevoked } from '../utils/session-family.js';
import { auditLog, auditLogDetached, safeInvokeHook, invokeHookDetached } from '../hooks/index.js';
import { enforceRateLimit } from '../rate-limit/enforce.js';
import { ipKey, emailKey } from '../rate-limit/keys.js';
import { withAttemptBudget } from '../security/attempt-budget.js';
import { assertTrustedOrigin } from '../middleware/csrf.js';

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

    // Every caller of issueSession has just authenticated the user (password+MFA, magic link, SSO, passkey).
    const authTime = Math.floor(Date.now() / 1000);
    const familyCreatedAt = new Date(authTime * 1000);
    const accessToken = await issueAccessToken(state, { sub: String(user.id), email: user.email, claims }, { authTime });
    const refreshTokenValue = generateOpaqueToken();
    const refreshTokenHash = hashOpaqueToken(state, refreshTokenValue);
    const expiresAt = cappedExpiry(state, familyCreatedAt, state.config.ttls.refreshToken);

    // Decided BEFORE this login's own session row exists — afterwards the device is always "known".
    const isNewDevice = await isNewDeviceForUser(state, { user, deviceInfo, deviceFingerprint, wasFirstLogin });

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
            kind: SESSION_KINDS.FIRST_PARTY,
            authTime: familyCreatedAt,
            familyId: newFamilyId(),
            familyCreatedAt,
            claims,
        },
        userId: user.id,
        lastLoginAt: new Date(),
    });

    if (isNewDevice) {
        notifyNewDevice({ hooks: state.hooks, logger: state.logger, req, user }).catch((err) => {
            state.logger?.warn?.({ err }, 'New-device notification failed (non-fatal)');
        });
    }

    return { accessToken, refreshTokenValue, refreshExpiresAt: expiresAt };
}

async function isNewDeviceForUser(state, { user, deviceInfo, deviceFingerprint, wasFirstLogin }) {
    if (wasFirstLogin || !deviceInfo) return false;
    try {
        return !(await state.storage.sessionRepository.existsForDevice(user.id, deviceFingerprint, deviceInfo));
    } catch (err) {
        state.logger?.warn?.({ err }, 'New-device detection failed (non-fatal)');
        return false;
    }
}

/** Clears both session cookies with the attributes they were set with — a clear without the same `domain`/`path` leaves a domain cookie in place. */
function clearSessionCookies(res, state) {
    const { httpOnly, secure, sameSite, path, domain } = cookieOptions(state);
    const opts = { httpOnly, secure, sameSite, path, ...(domain ? { domain } : {}) };
    res.clearCookie(COOKIE_NAMES.ACCESS_TOKEN, opts);
    res.clearCookie(COOKIE_NAMES.REFRESH_TOKEN, opts);
}

/**
 * The refresh token also appears in login/refresh JSON bodies (for non-browser clients) unless
 * `config.cookies.refreshTokenInBody` is false — set that for browser-only apps, so script on the
 * page (an XSS) can never read the long-lived token the httpOnly cookie is protecting.
 */
function refreshTokenInBody(state, value) {
    return state.config.cookies?.refreshTokenInBody === false ? {} : { refreshToken: value };
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

        await enforceRateLimit(state, `register:ip:${ipKey(req.ip)}`, state.config.rateLimiting.register, { failMode: 'closed' });
        await enforceRateLimit(state, `verification-email:${emailKey(state, email)}`, state.config.rateLimiting.verificationEmailByEmail, { failMode: 'closed' });

        // Hashed on every path, so timing doesn't leak whether the email was new.
        const passwordHash = await hashPassword(password, state.config.security.bcryptRounds);
        const existing = await state.storage.userRepository.findByEmail(email);

        if (existing?.status === IDENTITY_STATUS.PENDING_VERIFICATION) {
            // Nobody has proven they own this address yet, so an earlier registration's password
            // must not survive: otherwise an attacker pre-registers the victim's email with a
            // password they know, and the victim — whose own registration was silently accepted —
            // verifies the address and activates the ATTACKER's password. The newest registrant's
            // password replaces it, every earlier code/link dies, and a fresh code goes to the inbox.
            await state.storage.userRepository.updateById(existing.id, {
                passwordHash,
                profile: { firstName, lastName },
            });
            await state.storage.verificationTokenRepository.deleteAllForUser('email_verification', existing.id);
            const { token: verificationToken, verificationCode } = await createEmailVerificationToken(state, existing.id);
            auditLogDetached(state.logger, state.hooks, 'REGISTRATION_RESTARTED', { userId: String(existing.id) });
            invokeHookDetached(state.logger, state.hooks, 'onVerificationEmailRequested', { email, firstName, lastName, verificationToken, verificationCode });
            return res.status(201).json({ status: 'ok' });
        }
        if (existing) {
            // An active (or otherwise settled) account is never touched by a registration.
            return res.status(201).json({ status: 'ok' });
        }

        const user = await state.storage.userRepository.create({
            email,
            passwordHash,
            status: IDENTITY_STATUS.PENDING_VERIFICATION,
            profile: { firstName, lastName },
            // Written by whoever registers — persisted only when the app opted in (see registerSchema).
            metadata: state.config.registration.acceptMetadata === true ? (metadata || {}) : {},
        });

        const { token: verificationToken, verificationCode } = await createEmailVerificationToken(state, user.id);

        auditLogDetached(state.logger, state.hooks, 'REGISTERED', { userId: String(user.id), email });
        invokeHookDetached(state.logger, state.hooks, 'onVerificationEmailRequested', { email, firstName, lastName, verificationToken, verificationCode });

        res.status(201).json({ status: 'ok' });
    } catch (err) {
        next(err);
    }
}

const INVALID_VERIFICATION = () => new IdpError({ code: 'INVALID_OR_EXPIRED_TOKEN', httpStatus: 400, message: 'Invalid or expired verification token' });
const VERIFICATION_LOCKED = () => new IdpError({ code: 'VERIFICATION_LOCKED', httpStatus: 429, message: 'Too many failed verification attempts — request a new code.' });

async function createEmailVerificationToken(state, userId) {
    const token = generateOpaqueToken(32);
    const tokenHash = hashOpaqueToken(state, token);
    const verificationCode = crypto.randomInt(100000, 1000000).toString();
    await state.storage.verificationTokenRepository.create('email_verification', {
        user: userId,
        tokenHash,
        // Stored as an HMAC like every other token — a database read must not yield a usable code.
        verificationCode: hashOpaqueToken(state, verificationCode),
        expiresAt: new Date(Date.now() + state.config.ttls.emailVerification * 1000),
    });
    return { token, verificationCode };
}

export async function verifyEmailHandler(req, res, next) {
    try {
        const state = getState();
        const { email, token, code } = req.body;

        await enforceRateLimit(state, `email-verification:ip:${ipKey(req.ip)}`, state.config.rateLimiting.emailVerification, { failMode: 'closed' });

        // One answer for an unknown address, an already-verified one, and a wrong code — none of
        // them may reveal whether an account exists.
        const user = await state.storage.userRepository.findByEmail(email);
        if (!user || user.status !== IDENTITY_STATUS.PENDING_VERIFICATION) throw INVALID_VERIFICATION();

        const tokens = state.storage.verificationTokenRepository;
        await withAttemptBudget(state, `email-verification:${user.id}`, state.config.security.verificationCodeLockout, {
            lockedError: VERIFICATION_LOCKED,
            onLocked: async () => {
                // Budget spent: burn every outstanding code, so guessing has to start over against a
                // fresh code that only the inbox owner receives.
                await tokens.deleteAllForUser('email_verification', user.id);
                await auditLog(state.logger, state.hooks, 'EMAIL_VERIFICATION_LOCKED', { userId: String(user.id) });
            },
        }, async () => {
            const found = token
                ? await tokens.consumeByHash('email_verification', hashOpaqueToken(state, token), user.id)
                // Codes issued before 0.4.0 were stored in plain text; they expire within a day.
                : (await tokens.consumeByCode('email_verification', hashOpaqueToken(state, code), user.id))
                    ?? (await tokens.consumeByCode('email_verification', code, user.id));
            if (!found) throw INVALID_VERIFICATION();
        });

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

        await enforceRateLimit(state, `register:ip:${ipKey(req.ip)}`, state.config.rateLimiting.register, { failMode: 'closed' });
        await enforceRateLimit(state, `verification-email:${emailKey(state, email)}`, state.config.rateLimiting.verificationEmailByEmail, { failMode: 'closed' });

        // Same answer for unknown, already-verified and pending addresses (enumeration-safe).
        const user = await state.storage.userRepository.findByEmail(email);
        if (!user || user.status !== IDENTITY_STATUS.PENDING_VERIFICATION) return res.json({ status: 'ok' });

        await state.storage.verificationTokenRepository.deleteAllForUser('email_verification', user.id);
        const { token, verificationCode } = await createEmailVerificationToken(state, user.id);

        auditLogDetached(state.logger, state.hooks, 'VERIFICATION_TOKEN_REGENERATED', { userId: String(user.id) });
        invokeHookDetached(state.logger, state.hooks, 'onVerificationEmailRequested', {
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

        await enforceRateLimit(state, `login:ip:${ipKey(req.ip)}`, state.config.rateLimiting.login, { failMode: 'closed' });
        await enforceRateLimit(state, `login:email:${emailKey(state, email)}`, state.config.rateLimiting.loginByEmail, { failMode: 'closed' });

        let user = await state.storage.userRepository.findByEmail(email, { select: '+passwordHash' });

        if (user && user.status === IDENTITY_STATUS.LOCKED && user.lockUntil && user.lockUntil <= new Date()) {
            await state.storage.userRepository.updateById(user.id, { failedLoginAttempts: 0, lockUntil: null, status: IDENTITY_STATUS.ACTIVE });
            user.status = IDENTITY_STATUS.ACTIVE;
            user.failedLoginAttempts = 0;
            user.lockUntil = null;
        }

        const passwordValid = user ? await verifyPassword(password, user.passwordHash) : (await compareDummyPassword(password), false);

        // While an account is locked, the right password and a wrong one get the same answer — otherwise
        // the lock becomes a password oracle: guessing continues, and the one guess answered "locked"
        // instead of "invalid" is the password, ready for when the lock lifts. (The lock itself was
        // announced through onSuspiciousActivityDetected; a password reset lifts it.)
        if (user?.status === IDENTITY_STATUS.LOCKED) {
            throw new IdpError({ code: 'INVALID_CREDENTIALS', httpStatus: 401, message: 'Invalid email or password' });
        }

        if (!user || !passwordValid) {
            if (user && user.status === IDENTITY_STATUS.ACTIVE) {
                await handleFailedLogin(state, user);
            }
            throw new IdpError({ code: 'INVALID_CREDENTIALS', httpStatus: 401, message: 'Invalid email or password' });
        }

        assertUsableStatus(user);

        if (user.mfaEnabled) return res.json(await mfaChallengeResponse(state, user));

        const claims = await resolveClaims(state, user, { isNewUser: false, method: 'password' });
        const session = await issueSession(state, { user, claims, req });

        await auditLog(state.logger, state.hooks, 'LOGIN', { userId: String(user.id), email });

        setSessionCookies(res, state, session);
        res.json({
            accessToken: session.accessToken.token,
            accessTokenExpiresAt: session.accessToken.expiresAt,
            ...refreshTokenInBody(state, session.refreshTokenValue),
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

/**
 * The response every first-factor login (password, magic link, SSO) gives instead of a session when
 * the account has MFA: a short-lived challenge token to complete at /mfa/verify or /webauthn/mfa/verify.
 */
async function mfaChallengeResponse(state, user) {
    const mfaChallengeToken = await issueMfaChallengeToken(state, user.id);
    return { mfaRequired: true, mfaChallengeToken, expiresIn: state.config.ttls.mfaChallenge };
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
        await enforceRateLimit(state, `refresh:ip:${ipKey(req.ip)}`, state.config.rateLimiting.refreshToken);

        const cookieValue = req.cookies?.[COOKIE_NAMES.REFRESH_TOKEN];
        const refreshTokenValue = cookieValue || req.body?.refreshToken;
        if (!refreshTokenValue) throw new IdpError({ code: 'REFRESH_TOKEN_REQUIRED', httpStatus: 400, message: 'Refresh token is required' });
        if (refreshTokenValue === cookieValue) assertTrustedOrigin(state, req);

        const tokenHash = hashOpaqueToken(state, refreshTokenValue);
        const existing = await state.storage.sessionRepository.revokeByRefreshTokenHash(tokenHash, { reason: 'rotated' });
        if (!existing) {
            await handleRefreshReuse(state, tokenHash);
            throw new IdpError({ code: 'INVALID_REFRESH_TOKEN', httpStatus: 401, message: 'Invalid or expired refresh token' });
        }
        // An OAuth2 client's refresh token is redeemable only at /oauth2/token by that client — never
        // here, where it would mint a first-party session without client authentication. The row was
        // just consumed above; it stays revoked, since a client token showing up here means it leaked.
        if (sessionKindOf(existing) !== SESSION_KINDS.FIRST_PARTY) {
            state.logger?.warn?.({ userId: String(existing.user) }, 'OAuth2 refresh token presented at /refresh — refused and revoked');
            throw new IdpError({ code: 'INVALID_REFRESH_TOKEN', httpStatus: 401, message: 'Invalid or expired refresh token' });
        }

        // Default (narrow) select would be enough for the status check alone,
        // but a full user is fetched so resolveAuthContext gets the same
        // shape of `user` it gets from every other login path, in case
        // config.session.reresolveClaimsOnRefresh is enabled below.
        const user = await state.storage.userRepository.findById(existing.user);
        if (!user || user.status !== IDENTITY_STATUS.ACTIVE) throw new IdpError({ code: 'USER_NOT_ACTIVE', httpStatus: 403, message: 'User account is not active' });

        const claims = state.config.session.reresolveClaimsOnRefresh
            ? await resolveClaims(state, user, { isNewUser: false, method: 'refresh' })
            : existing.claims || {};

        // A refresh is not an authentication: the original login time carries over (a row from
        // before 0.4.0 has none, which requireRecentAuth treats as "not recent").
        const authTime = existing.authTime ? Math.floor(new Date(existing.authTime).getTime() / 1000) : undefined;
        // The family's absolute end applies however actively it's been refreshed.
        const { familyId, familyCreatedAt } = familyOf(existing);
        if (familyEndsAt(state, familyCreatedAt) <= new Date()) {
            throw new IdpError({ code: 'INVALID_REFRESH_TOKEN', httpStatus: 401, message: 'Session has reached its maximum lifetime — please sign in again' });
        }

        const accessToken = await issueAccessToken(state, { sub: String(user.id), email: user.email, claims }, { authTime });
        const newRefreshTokenValue = generateOpaqueToken();
        const newRefreshTokenHash = hashOpaqueToken(state, newRefreshTokenValue);
        const refreshExpiresAt = cappedExpiry(state, familyCreatedAt, state.config.ttls.refreshToken);
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
            kind: SESSION_KINDS.FIRST_PARTY,
            authTime: existing.authTime ?? null,
            familyId,
            familyCreatedAt,
            claims,
        });
        await assertChainNotRevoked(state, user.id, existing.createdAt, newRefreshTokenHash);

        await state.cache.set(`${CACHE_KEY_PREFIXES.REVOKED_REFRESH_TOKEN}:${existing.jti}`, '1', state.config.ttls.revocationCache);

        await auditLog(state.logger, state.hooks, 'TOKEN_REFRESHED', { userId: String(user.id) });

        setSessionCookies(res, state, { accessToken, refreshTokenValue: newRefreshTokenValue, refreshExpiresAt });
        res.json({ accessToken: accessToken.token, accessTokenExpiresAt: accessToken.expiresAt, ...refreshTokenInBody(state, newRefreshTokenValue), refreshTokenExpiresAt: refreshExpiresAt });
    } catch (err) {
        next(err);
    }
}

export async function logoutHandler(req, res, next) {
    try {
        const state = getState();
        const refreshTokenValue = req.body?.refreshToken || req.cookies?.[COOKIE_NAMES.REFRESH_TOKEN];
        if (!refreshTokenValue) throw new IdpError({ code: 'REFRESH_TOKEN_REQUIRED', httpStatus: 400, message: 'Refresh token is required to log out' });
        if (!req.body?.refreshToken) assertTrustedOrigin(state, req);

        const tokenHash = hashOpaqueToken(state, refreshTokenValue);
        const existing = await state.storage.sessionRepository.revokeByRefreshTokenHash(tokenHash, { onlyIfActive: false });
        if (existing?.jti) {
            await state.cache.set(`${CACHE_KEY_PREFIXES.REVOKED_REFRESH_TOKEN}:${existing.jti}`, '1', state.config.ttls.revocationCache);
        }

        await auditLog(state.logger, state.hooks, 'LOGOUT', { userId: String(existing?.user ?? req.auth?.userId ?? 'unknown') });
        clearSessionCookies(res, state);
        res.json({ status: 'ok' });
    } catch (err) {
        next(err);
    }
}

export async function logoutAllHandler(req, res, next) {
    try {
        const state = getState();
        if (!req.auth?.userId) throw new IdpError({ code: 'UNAUTHENTICATED', httpStatus: 401, message: 'Authentication required' });

        await revokeAllUserSessions(state, req.auth.userId);
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

        await enforceRateLimit(state, `password-reset:ip:${ipKey(req.ip)}`, state.config.rateLimiting.passwordReset, { failMode: 'closed' });
        // Per address too: per-IP alone lets a distributed sender flood one inbox.
        await enforceRateLimit(state, `password-reset:email:${emailKey(state, email)}`, state.config.rateLimiting.passwordResetByEmail, { failMode: 'closed' });

        const user = await state.storage.userRepository.findByEmail(email);
        if (!user || user.status === IDENTITY_STATUS.DELETED) return res.json({ status: 'ok' }); // enumeration-safe

        // Only the newest link works: requesting another invalidates the earlier ones.
        await state.storage.verificationTokenRepository.deleteAllForUser('password_reset', user.id);
        const resetToken = generateOpaqueToken(32);
        await state.storage.verificationTokenRepository.create('password_reset', {
            user: user.id,
            tokenHash: hashOpaqueToken(state, resetToken),
            expiresAt: new Date(Date.now() + state.config.ttls.passwordReset * 1000),
        });

        invokeHookDetached(state.logger, state.hooks, 'onPasswordResetRequested', {
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
        // Proving the inbox and setting a new password also lifts a lockout (the lock exists to stop
        // password guessing — the guessed password is gone).
        const unlock = user.status === IDENTITY_STATUS.LOCKED ? { status: IDENTITY_STATUS.ACTIVE, failedLoginAttempts: 0, lockUntil: null } : {};
        await state.storage.userRepository.updateById(record.user, { passwordHash, passwordChangedAt: new Date(), ...unlock });
        await revokeAllUserSessions(state, record.user);
        // Any other outstanding reset links die with this one.
        await state.storage.verificationTokenRepository.deleteAllForUser('password_reset', record.user);

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
        await revokeAllUserSessions(state, userId);

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

        await revokeAllUserSessions(state, req.auth.userId);
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

        const result = await revokeAllUserSessions(state, req.auth.userId);
        await auditLog(state.logger, state.hooks, 'SESSIONS_REVOKED_ALL', { userId: req.auth.userId, revokedCount: result.revokedCount });
        res.json({ status: 'ok', revokedCount: result.revokedCount });
    } catch (err) {
        next(err);
    }
}

export { issueSession, setSessionCookies, clearSessionCookies, refreshTokenInBody, resolveClaims, cookieOptions, assertUsableStatus, mfaChallengeResponse };
