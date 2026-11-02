import crypto from 'crypto';
import { getState } from '../config/state.js';
import { IdpError } from '../errors/idp-error.js';
import { IDENTITY_STATUS, COOKIE_NAMES, CACHE_KEY_PREFIXES, SESSION_KINDS } from '../config/constants.js';
import { sessionKindOf } from '../utils/session-kind.js';
import { issueAccessToken, issueMfaChallengeToken, hashOpaqueToken, generateOpaqueToken, lookupByTokenHash, opaqueTokenHashes, HASH_PURPOSES } from '../signing/token.service.js';
import { hashPassword, verifyPassword, compareDummyPassword } from '../utils/password.js';
import { buildDeviceFingerprint, notifyNewDevice } from '../utils/device-fingerprint.js';
import { newFamilyId, familyOf, familyEndsAt, cappedExpiry, handleRefreshReuse, revokeAllUserSessions, assertChainNotRevoked, assertFamilyNotRevoked, peekRefreshRow, currentSessionEpoch, resolveRefreshTokenHash } from '../utils/session-family.js';
import { auditLog, auditLogDetached, safeInvokeHook, invokeHookDetached } from '../hooks/index.js';
import { enforceRateLimit } from '../rate-limit/enforce.js';
import { ipKey, emailKey } from '../rate-limit/keys.js';
import { withAttemptBudget } from '../security/attempt-budget.js';
import { assertTrustedOrigin } from '../middleware/csrf.js';
import { effectiveStatus, isActiveAccount, isPasswordLocked } from '../utils/account-status.js';
import { sessionCookieName, cookiesAreSecure, hostCookieName, readCookie, refreshCookieNames, sessionCookiePath, refreshCookieBinding, readRefreshCookie } from '../utils/cookies.js';
import { bindLoginChallenge } from '../oauth2/login-challenge.js';

function cookieOptions(state) {
    const c = state.config.cookies || {};
    return {
        httpOnly: true,
        secure: cookiesAreSecure(state),
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
/**
 * The session is created in the user's `sessionEpoch` as read when this sign-in loaded the user —
 * before it checked any credential — or, completing an MFA challenge, the epoch the challenge carries
 * (read before the first factor). A "sign out everywhere" after that read (e.g. a password reset that
 * landed while the old password was being checked) ends the session this call creates.
 */
async function issueSession(state, { user, claims, req, sessionEpoch: epochOverride, loginChallenge }) {
    const sessionEpoch = Number.isInteger(epochOverride) ? epochOverride
        : Number.isInteger(user.sessionEpoch) ? user.sessionEpoch : await currentSessionEpoch(state, user.id);
    const wasFirstLogin = !user.lastLoginAt;
    const deviceInfo = req.headers['user-agent'] || '';
    const deviceFingerprint = buildDeviceFingerprint(deviceInfo);

    // Every caller of issueSession has just authenticated the user (password+MFA, magic link, SSO, passkey).
    const authTime = Math.floor(Date.now() / 1000);
    const familyCreatedAt = new Date(authTime * 1000);
    const accessToken = await issueAccessToken(state, { sub: String(user.id), email: user.email, claims }, { authTime });
    const refreshTokenValue = generateOpaqueToken();
    const refreshTokenHash = hashOpaqueToken(state, refreshTokenValue, HASH_PURPOSES.REFRESH_TOKEN);
    const expiresAt = cappedExpiry(state, familyCreatedAt, state.config.ttls.refreshToken);

    // Decided BEFORE this login's own session row exists — afterwards the device is always "known".
    const isNewDevice = await isNewDeviceForUser(state, { user, deviceInfo, deviceFingerprint, wasFirstLogin });

    // The login below clears the failed-password counter and lockUntil. A row locked before 0.4.0 also
    // carries status LOCKED, which without a lockUntil would read as an administrative lock — so it is
    // normalised here (see account-status.js).
    if (user.status === IDENTITY_STATUS.LOCKED && user.lockUntil) {
        await state.storage.userRepository.updateById(user.id, { status: IDENTITY_STATUS.ACTIVE });
    }

    const familyId = newFamilyId();
    await state.storage.sessionRepository.createSessionForLogin({
        accessTokenAudit: { user: user.id, tokenHash: hashOpaqueToken(state, accessToken.token, HASH_PURPOSES.ACCESS_TOKEN_AUDIT), expiresAt: accessToken.expiresAt, kid: accessToken.kid, jti: accessToken.jti, ipAddress: req.ip, deviceInfo },
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
            familyId,
            familyCreatedAt,
            sessionEpoch,
            claims,
        },
        userId: user.id,
        lastLoginAt: new Date(),
    });
    await assertChainNotRevoked(state, user.id, sessionEpoch, refreshTokenHash, familyId);
    await bindLoginChallenge(state, loginChallenge, familyId);

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

/** Clears the session cookies with the attributes they were set with — a clear without the same `domain`/`path` leaves a domain cookie in place. */
function clearSessionCookies(req, res, state) {
    const { httpOnly, secure, sameSite, path, domain } = cookieOptions(state);
    const opts = { httpOnly, secure, sameSite, path, ...(domain ? { domain } : {}) };
    const names = refreshCookieNames(state);
    res.clearCookie(sessionCookieName(state, COOKIE_NAMES.ACCESS_TOKEN), opts);
    res.clearCookie(names.token, { ...opts, path: sessionCookiePath(state, req) });
    res.clearCookie(names.binding, opts);
    // The refresh cookie of earlier 0.4.0 builds (Path=/) — so a browser doesn't keep sending a live token everywhere.
    res.clearCookie(sessionCookieName(state, COOKIE_NAMES.REFRESH_TOKEN), opts);
}

/**
 * Whether the refresh token also appears in a login/refresh JSON body (`config.cookies.refreshTokenInBody`):
 * - `'auto'` (default) — only for non-browser clients. A browser request (it carries `Sec-Fetch-Site`
 *   or `Origin`, which page script can't remove) gets the token in its httpOnly cookie only, so script
 *   on the page (an XSS) never reads the long-lived token the cookie is protecting;
 * - `true` — always (a browser app that keeps the refresh token itself, e.g. cross-site without cookies);
 * - `false` — never.
 */
function refreshTokenInBody(state, req, value) {
    const mode = state.config.cookies?.refreshTokenInBody ?? 'auto';
    if (mode === false) return {};
    if (mode === 'auto' && (req.headers?.['sec-fetch-site'] !== undefined || req.headers?.origin !== undefined)) return {};
    return { refreshToken: value };
}

/** The access-token cookie (`Path=/`), and the refresh-token cookie scoped to the session endpoints with its binding (see readRefreshCookie). */
function setSessionCookies(req, res, state, { accessToken, refreshTokenValue, refreshExpiresAt }) {
    const opts = cookieOptions(state);
    const names = refreshCookieNames(state);
    res.cookie(sessionCookieName(state, COOKIE_NAMES.ACCESS_TOKEN), accessToken.token, { ...opts, expires: accessToken.expiresAt });
    res.cookie(names.token, refreshTokenValue, { ...opts, path: sessionCookiePath(state, req), expires: refreshExpiresAt });
    res.cookie(names.binding, refreshCookieBinding(state, refreshTokenValue), { ...opts, expires: refreshExpiresAt });
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
        // Every answer carries a ticket for the address (see issueVerificationTicket).
        const ticket = await issueVerificationTicket(state, req, res, email);
        const answer = () => res.status(201).json({ status: 'ok', verificationTicket: ticket });

        if (existing?.status === IDENTITY_STATUS.PENDING_VERIFICATION) {
            // A second registration for an address nobody has proven they own. Either order is an
            // attack on the inbox owner: "attacker first" makes the victim's verification activate the
            // attacker's password; "victim first" lets the attacker re-register right after the victim,
            // so the newest code in the victim's inbox activates the attacker's password. So each code
            // is bound to the password registered with it (on its own row), earlier codes stay valid,
            // and from now on verifying needs that password too (`registrationContested`): the inbox
            // owner activates THEIR registration, and a code from anyone else's is useless to them.
            // (The account's profile stays as the first registration set it.)
            // Conditional on the account STILL being pending: if its owner activated it since it was read
            // (verify-email, magic link, SSO, reset), an unconditional write would put this registrant's
            // password on a live account.
            const contested = await state.storage.userRepository.updateByIdIfStatus(existing.id, IDENTITY_STATUS.PENDING_VERIFICATION, { passwordHash, registrationContested: true });
            if (!contested) return answer();
            const { token: verificationToken, verificationCode } = await createEmailVerificationToken(state, existing.id, passwordHash, email);
            auditLogDetached(state.logger, state.hooks, 'REGISTRATION_REPEATED', { userId: String(existing.id) });
            invokeHookDetached(state.logger, state.hooks, 'onVerificationEmailRequested', { email, firstName, lastName, verificationToken, verificationCode });
            return answer();
        }
        if (existing) {
            // An active (or otherwise settled) account is never touched by a registration.
            return answer();
        }

        const user = await state.storage.userRepository.create({
            email,
            passwordHash,
            status: IDENTITY_STATUS.PENDING_VERIFICATION,
            profile: { firstName, lastName },
            // Written by whoever registers — persisted only when the app opted in (see registerSchema).
            metadata: state.config.registration.acceptMetadata === true ? (metadata || {}) : {},
        });

        const { token: verificationToken, verificationCode } = await createEmailVerificationToken(state, user.id, passwordHash, email);

        auditLogDetached(state.logger, state.hooks, 'REGISTERED', { userId: String(user.id), email });
        invokeHookDetached(state.logger, state.hooks, 'onVerificationEmailRequested', { email, firstName, lastName, verificationToken, verificationCode });

        answer();
    } catch (err) {
        next(err);
    }
}

const INVALID_VERIFICATION = () => new IdpError({ code: 'INVALID_OR_EXPIRED_TOKEN', httpStatus: 400, message: 'Invalid or expired verification token' });
const VERIFICATION_LOCKED = () => new IdpError({ code: 'VERIFICATION_LOCKED', httpStatus: 429, message: 'Too many failed verification attempts — use the link in the verification email.' });
/** The lifetime cap's window: long enough to outlive any pending registration's codes. */
const CODE_LIFETIME_CAP_SECONDS = 365 * 24 * 60 * 60;
const REGISTRATION_PASSWORD_REQUIRED = () => new IdpError({
    code: 'REGISTRATION_PASSWORD_REQUIRED',
    httpStatus: 400,
    message: 'This address was registered more than once before it was verified — enter the password you registered with, together with the code from that registration\'s email.',
});
const LEGACY_CODE = /^\d{6}$/;

/**
 * Verification tickets. The 6-digit code is guessable, so attempts at it are budgeted — and a budget
 * anyone can spend is one a stranger can use up for the address's owner. So whoever registers (or asks
 * for a resend) gets a ticket — a host-only cookie, also in the JSON body for clients without cookies —
 * and code attempts carrying a ticket issued for that ADDRESS spend the ticket's own budget. Attempts
 * without one share a per-address budget, which a stranger can use up without affecting the browser
 * that registered (and the emailed link always works).
 *
 * Tickets are per address, not per account, and are stored for every caller whether or not the address
 * has an account: what a ticket can do never depends on the account, so it can't tell anyone whether
 * there is one. At most MAX_VERIFICATION_TICKETS are stored per address and code lifetime (later ones
 * are handed out but not stored); a caller that already holds a live ticket for the address keeps it.
 * Every budget lasts the code's lifetime, so the guesses at a code are bounded:
 * maxFailedAttempts × (1 + MAX_VERIFICATION_TICKETS).
 */
const MAX_VERIFICATION_TICKETS = 5;
const ticketCookie = (state) => hostCookieName(cookiesAreSecure(state), 'verification_ticket');
const ticketKey = (state, email, hash) => `verification-ticket:${emailKey(state, email)}:${hash}`;

/** The code budgets' limits: never shorter than the code's lifetime, whatever is configured. */
function codeBudgetLimits(state) {
    const ttl = state.config.ttls.emailVerification;
    const { maxFailedAttempts, windowSeconds, lockSeconds } = state.config.security.verificationCodeLockout;
    return { maxFailedAttempts, windowSeconds: Math.max(windowSeconds, ttl), lockSeconds: Math.max(lockSeconds, ttl) };
}

/** The live ticket for `email` the request carries (`raw` from the body if given, else the cookie): `{ raw, hash }` or null. */
async function presentedTicket(state, email, raw) {
    if (typeof raw !== 'string' || !raw) return null;
    for (const hash of opaqueTokenHashes(state, raw, HASH_PURPOSES.EMAIL_VERIFICATION_TICKET)) {
        const entry = await state.attemptCounters.get(ticketKey(state, email, hash));
        if (entry && new Date(entry.windowExpiresAt) > new Date()) return { raw, hash };
    }
    return null;
}

/** Sets (and returns) the caller's ticket for `email` — the live one it holds, or a new one. Same work for every address. */
async function issueVerificationTicket(state, req, res, email) {
    let ticket = (await presentedTicket(state, email, readCookie(req, ticketCookie(state))))?.raw;
    if (!ticket) {
        ticket = generateOpaqueToken(32);
        const ttl = state.config.ttls.emailVerification;
        const quota = await state.attemptCounters.recordFailure(`verification-tickets:${emailKey(state, email)}`, { max: MAX_VERIFICATION_TICKETS, windowSeconds: ttl, lockSeconds: ttl });
        if (quota.count <= MAX_VERIFICATION_TICKETS) {
            await state.attemptCounters.recordFailure(ticketKey(state, email, hashOpaqueToken(state, ticket, HASH_PURPOSES.EMAIL_VERIFICATION_TICKET)), { max: 1, windowSeconds: ttl, lockSeconds: ttl });
        }
    }
    res.cookie(ticketCookie(state), ticket, {
        httpOnly: true, secure: cookiesAreSecure(state), sameSite: 'lax', path: '/', maxAge: state.config.ttls.emailVerification * 1000,
    });
    return ticket;
}

/** The password a verification activates: the one bound to its code (rows from before 0.4.0: the account's). */
const boundPasswordHash = (row, user) => row.passwordHash ?? user.passwordHash ?? null;

/**
 * At most this many 6-digit codes are issued per address per code lifetime; later verification emails
 * carry only the link (`verificationCode: null`). Every live code is a target for each guess (a
 * contested registration keeps several live), so this bounds how many a guess is tried against.
 */
const MAX_CODES_PER_ADDRESS = 3;

/** `passwordHash`: the password of the registration this code verifies — the one it activates. */
async function createEmailVerificationToken(state, userId, passwordHash, email) {
    const ttl = state.config.ttls.emailVerification;
    const token = generateOpaqueToken(32);
    const tokenHash = hashOpaqueToken(state, token, HASH_PURPOSES.EMAIL_VERIFICATION_LINK);
    const quota = await state.attemptCounters.recordFailure(`verification-codes:${emailKey(state, email)}`, { max: MAX_CODES_PER_ADDRESS, windowSeconds: ttl, lockSeconds: ttl });
    const verificationCode = quota.count <= MAX_CODES_PER_ADDRESS ? crypto.randomInt(100000, 1000000).toString() : null;
    await state.storage.verificationTokenRepository.create('email_verification', {
        user: userId,
        tokenHash,
        // Stored as an HMAC like every other token — a database read must not yield a usable code.
        verificationCode: verificationCode ? hashOpaqueToken(state, verificationCode, HASH_PURPOSES.EMAIL_VERIFICATION_CODE) : null,
        passwordHash: passwordHash ?? null,
        expiresAt: new Date(Date.now() + ttl * 1000),
    });
    return { token, verificationCode };
}

export async function verifyEmailHandler(req, res, next) {
    try {
        const state = getState();
        const { email, token, code, password } = req.body;

        await enforceRateLimit(state, `email-verification:ip:${ipKey(req.ip)}`, state.config.rateLimiting.emailVerification, { failMode: 'closed' });

        // One answer for an unknown address, an already-verified one, and a wrong code — none of
        // them may reveal whether an account exists.
        const user = await state.storage.userRepository.findByEmail(email, { select: '+passwordHash' });
        const tokens = state.storage.verificationTokenRepository;

        const verify = async () => {
            if (!user || user.status !== IDENTITY_STATUS.PENDING_VERIFICATION) throw INVALID_VERIFICATION();
            // Read, check, THEN consume — a refused attempt never takes the code out of circulation.
            const row = token
                ? (await lookupByTokenHash(state, token, HASH_PURPOSES.EMAIL_VERIFICATION_LINK, (tokenHash) => tokens.findActive('email_verification', { tokenHash }, user.id))).result
                : (await lookupByTokenHash(state, code, HASH_PURPOSES.EMAIL_VERIFICATION_CODE, (verificationCode) => tokens.findActive('email_verification', { verificationCode }, user.id))).result
                    // Codes issued before 0.4.0 were stored in plain text (they expire within a day). Only
                    // a real 6-digit code is tried that way — never a value read from the database, which
                    // is now the code's HMAC and would otherwise be accepted as-is.
                    ?? (LEGACY_CODE.test(code) ? await tokens.findActive('email_verification', { verificationCode: code }, user.id) : null);
            if (!row) throw INVALID_VERIFICATION();
            if (user.registrationContested) {
                // No password: say what's missing. A wrong one: the same answer as a wrong code.
                if (!password) throw REGISTRATION_PASSWORD_REQUIRED();
                if (!(await verifyPassword(password, boundPasswordHash(row, user)))) throw INVALID_VERIFICATION();
            }
            const consumed = token
                ? await tokens.consumeByHash('email_verification', row.tokenHash, user.id)
                : await tokens.consumeByCode('email_verification', row.verificationCode, user.id);
            if (!consumed) throw INVALID_VERIFICATION(); // a concurrent request used it first
            return consumed;
        };

        // The 6-digit CODE is guessable, so attempts at it are budgeted: per verification ticket when the
        // request carries a live one for this address (see issueVerificationTicket), otherwise per ADDRESS
        // — the same for unknown, verified and pending addresses, so nothing here says which it is. A
        // spent budget locks only its own attempts: the codes stay valid for the ticket holder, and the
        // 256-bit link can't be guessed at all.
        const pendingUser = user?.status === IDENTITY_STATUS.PENDING_VERIFICATION ? user : null;
        const ticket = token ? null : await presentedTicket(state, email, typeof req.body.ticket === 'string' ? req.body.ticket : readCookie(req, ticketCookie(state)));
        const budgetKey = ticket ? `email-verification:ticket:${ticket.hash}` : `email-verification:${emailKey(state, email)}`;
        // Inside that budget, every guess also counts toward the address's year-long cap
        // (`maxTotalFailedAttempts`, ticket or not): however long someone keeps registering and guessing,
        // codes for this address are guessed at most that many times a year — then only the link works.
        // The trade-off, deliberately: anyone can spend the cap and switch an address to link-only (for its
        // registrant too). Exempting the registrant's ticket would also exempt an attacker who registers
        // the same address, and each such ticket would be guesses beyond any bound.
        const capped = () => withAttemptBudget(state, `email-verification-total:${emailKey(state, email)}`, {
            maxFailedAttempts: state.config.security.verificationCodeLockout.maxTotalFailedAttempts, windowSeconds: CODE_LIFETIME_CAP_SECONDS, lockSeconds: CODE_LIFETIME_CAP_SECONDS,
        }, { lockedError: VERIFICATION_LOCKED }, verify);
        const found = token ? await verify() : await withAttemptBudget(state, budgetKey, codeBudgetLimits(state), {
            lockedError: VERIFICATION_LOCKED,
            onLocked: async () => {
                if (!pendingUser) return;
                await auditLog(state.logger, state.hooks, 'EMAIL_VERIFICATION_LOCKED', { userId: String(pendingUser.id), withTicket: Boolean(ticket) });
            },
        }, capped);

        const activated = await state.storage.userRepository.updateByIdIfStatus(user.id, IDENTITY_STATUS.PENDING_VERIFICATION, {
            status: IDENTITY_STATUS.ACTIVE, failedLoginAttempts: 0, lockUntil: null,
            passwordHash: boundPasswordHash(found, user), registrationContested: false,
        });
        if (!activated) throw INVALID_VERIFICATION(); // settled meanwhile by another path
        await state.storage.verificationTokenRepository.deleteAllForUser('email_verification', user.id);
        if (ticket) await state.attemptCounters.reset(ticketKey(state, email, ticket.hash));
        res.clearCookie(ticketCookie(state), { httpOnly: true, secure: cookiesAreSecure(state), sameSite: 'lax', path: '/' });

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

        // Same answer — and the same timing — for unknown, already-verified and pending addresses: the
        // lookup and the writes run after the response (see runAfterResponse). The ticket is issued the
        // same way for every address (see issueVerificationTicket).
        const ticket = await issueVerificationTicket(state, req, res, email);
        res.json({ status: 'ok', verificationTicket: ticket });
        runAfterResponse(state, 'Resend of the verification email', async () => {
            const user = await state.storage.userRepository.findByEmail(email, { select: '+passwordHash' });
            if (!user || user.status !== IDENTITY_STATUS.PENDING_VERIFICATION) return;

            // Normally only the newest code works. While registrations compete for the address, each
            // one's code stays valid (the new one is bound to the most recent registration's password).
            if (!user.registrationContested) await state.storage.verificationTokenRepository.deleteAllForUser('email_verification', user.id);
            const { token, verificationCode } = await createEmailVerificationToken(state, user.id, user.passwordHash, email);

            auditLogDetached(state.logger, state.hooks, 'VERIFICATION_TOKEN_REGENERATED', { userId: String(user.id) });
            invokeHookDetached(state.logger, state.hooks, 'onVerificationEmailRequested', {
                email, firstName: user.profile?.firstName, lastName: user.profile?.lastName, verificationToken: token, verificationCode,
            });
        });
    } catch (err) {
        next(err);
    }
}

/**
 * For the enumeration-sensitive "send me an email" endpoints: the answer is the same for every address,
 * and so must be the time it takes — a lookup plus writes for a real account, nothing for an unknown
 * one, is measurable. The work runs after the response is sent; a failure is logged (the caller has
 * been told "ok" either way, exactly as it would be for an unknown address).
 */
function runAfterResponse(state, what, work) {
    setImmediate(() => {
        work().catch((err) => state.logger?.error?.({ err }, `${what} failed`));
    });
}

// ── Login ────────────────────────────────────────────────────────────────

export async function loginHandler(req, res, next) {
    try {
        const state = getState();
        const { email, password } = req.body;
        assertTrustedOrigin(state, req); // sets session cookies — refuse login CSRF (see middleware/csrf.js)

        await enforceRateLimit(state, `login:ip:${ipKey(req.ip)}`, state.config.rateLimiting.login, { failMode: 'closed' });
        await enforceRateLimit(state, `login:email:${emailKey(state, email)}`, state.config.rateLimiting.loginByEmail, { failMode: 'closed' });

        // Loaded BEFORE the password is checked: its sessionEpoch is the one the new session belongs to.
        const user = await state.storage.userRepository.findByEmail(email, { select: '+passwordHash' });

        if (user?.lockUntil && new Date(user.lockUntil) <= new Date()) {
            // A lock recorded on the account before 0.4.0 has run out (it was also a LOCKED status then).
            const statusFix = user.status === IDENTITY_STATUS.LOCKED ? { status: IDENTITY_STATUS.ACTIVE } : {};
            await state.storage.userRepository.updateById(user.id, { failedLoginAttempts: 0, lockUntil: null, ...statusFix });
            Object.assign(user, { failedLoginAttempts: 0, lockUntil: null, ...statusFix });
        }

        const passwordValid = user ? await checkPasswordWithBudget(state, user, password) : (await compareDummyPassword(password), false);

        // While password login is locked, the right password and a wrong one get the same answer —
        // otherwise the lock becomes a password oracle: guessing continues, and the one guess answered
        // "locked" instead of "invalid" is the password, ready for when the lock lifts. (The lock itself
        // was announced through onSuspiciousActivityDetected; a password reset lifts it, and every other
        // sign-in method keeps working meanwhile.)
        //
        // A not-yet-verified account answers the same as a wrong password, right password or not: a
        // distinct "pending" answer for the right one tells whoever registered it whether their password
        // is still the current one — i.e. exactly when someone else registered the same address.
        if (!user || !passwordValid || isPasswordLocked(user) || effectiveStatus(user) === IDENTITY_STATUS.PENDING_VERIFICATION) {
            throw new IdpError({ code: 'INVALID_CREDENTIALS', httpStatus: 401, message: 'Invalid email or password' });
        }

        assertUsableStatus(user);

        const loginChallenge = req.body.login_challenge;
        if (user.mfaEnabled) return res.json(await mfaChallengeResponse(state, user, { loginChallenge }));

        const claims = await resolveClaims(state, user, { isNewUser: false, method: 'password' });
        const session = await issueSession(state, { user, claims, req, loginChallenge });

        await auditLog(state.logger, state.hooks, 'LOGIN', { userId: String(user.id), email });

        setSessionCookies(req, res, state, session);
        res.json({
            accessToken: session.accessToken.token,
            accessTokenExpiresAt: session.accessToken.expiresAt,
            ...refreshTokenInBody(state, req, session.refreshTokenValue),
            refreshTokenExpiresAt: session.refreshExpiresAt,
            userId: String(user.id),
        });
    } catch (err) {
        next(err);
    }
}

const passwordLoginKey = (userId) => `password-login:${userId}`;
const WRONG_PASSWORD = 'WRONG_PASSWORD';

/**
 * Checks the password inside the per-account attempt budget (`maxFailedLoginAttempts` per
 * `accountLockDurationMs`, then locked as long) — PASSWORD login only, never the account. The attempt
 * is counted BEFORE bcrypt runs, so a concurrent burst gets no more guesses than the budget (counting
 * after a failure let every request of a burst be checked). A success resets the count; other sign-in
 * methods don't touch it, so the owner signing in by magic link doesn't hand a guesser a fresh budget.
 * Returns whether the password is right; false while locked. A locked attempt still spends a bcrypt
 * compare, so its timing doesn't stand out.
 */
async function checkPasswordWithBudget(state, user, password) {
    // Nothing to guess (no password) or nothing to sign in to yet (pending): no budget to spend, and no
    // "suspicious activity" mail an attacker could trigger at will. The compare still runs, for timing.
    if (!user.passwordHash || !isActiveAccount(user)) return verifyPassword(password, user.passwordHash);
    const { maxFailedLoginAttempts, accountLockDurationMs } = state.config.security;
    const seconds = Math.ceil(accountLockDurationMs / 1000);
    let checked = false;
    try {
        return await withAttemptBudget(state, passwordLoginKey(user.id), { maxFailedAttempts: maxFailedLoginAttempts, windowSeconds: seconds, lockSeconds: seconds }, {
            lockedError: () => Object.assign(new Error('password login locked'), { code: 'PASSWORD_LOGIN_LOCKED' }),
            isFailure: (err) => err?.code === WRONG_PASSWORD,
            onLocked: (entry) => onPasswordLoginLocked(state, user, entry),
        }, async () => {
            checked = true;
            if (!(await verifyPassword(password, user.passwordHash))) throw Object.assign(new Error('wrong password'), { code: WRONG_PASSWORD });
            return true;
        });
    } catch (err) {
        if (err?.code === WRONG_PASSWORD) return false;
        if (err?.code === 'PASSWORD_LOGIN_LOCKED') {
            if (!checked) await compareDummyPassword(password);
            return false;
        }
        throw err;
    }
}

async function onPasswordLoginLocked(state, user, entry) {
    const failedAttempts = entry?.count ?? state.config.security.maxFailedLoginAttempts;
    const unlocksAt = new Date(Date.now() + state.config.security.accountLockDurationMs);
    await auditLog(state.logger, state.hooks, 'ACCOUNT_LOCKED', { userId: String(user.id), failedAttempts });
    await safeInvokeHook(state.logger, state.hooks, 'onSuspiciousActivityDetected', {
        userId: String(user.id), email: user.email, firstName: user.profile?.firstName || '', lastName: user.profile?.lastName || '',
        locale: user.profile?.locale || 'en', when: new Date().toISOString(), failedAttempts, unlocksAt: unlocksAt.toISOString(),
    });
}

/**
 * The response every first-factor login (password, magic link, SSO) gives instead of a session when
 * the account has MFA: a short-lived challenge token to complete at /mfa/verify or /webauthn/mfa/verify.
 */
async function mfaChallengeResponse(state, user, { loginChallenge } = {}) {
    // `user` was loaded before its first factor was checked: the challenge carries that epoch.
    const sessionEpoch = Number.isInteger(user.sessionEpoch) ? user.sessionEpoch : await currentSessionEpoch(state, user.id);
    const mfaChallengeToken = await issueMfaChallengeToken(state, user.id, { sessionEpoch, loginChallenge });
    return { mfaRequired: true, mfaChallengeToken, expiresIn: state.config.ttls.mfaChallenge };
}

/** Refuses an account that may not sign in. A password lockout is not checked here — see account-status.js. */
function assertUsableStatus(user) {
    switch (effectiveStatus(user)) {
        case IDENTITY_STATUS.LOCKED:
            throw new IdpError({ code: 'ACCOUNT_LOCKED', httpStatus: 423, message: 'Account is locked' });
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

        // Checked first, and for a body token too: /session/refresh sets session cookies, so a form posting
        // the ATTACKER's refresh token from a sibling origin would sign the victim's browser into the
        // attacker's account.
        assertTrustedOrigin(state, req);
        // A token in the body is explicit and wins over the cookie.
        const refreshTokenValue = req.body?.refreshToken || readRefreshCookie(state, req);
        if (!refreshTokenValue) throw new IdpError({ code: 'REFRESH_TOKEN_REQUIRED', httpStatus: 400, message: 'Refresh token is required' });

        const tokenHash = await resolveRefreshTokenHash(state, refreshTokenValue);
        // Everything that can refuse or fail runs BEFORE the token is consumed: a refusal (an inactive
        // account, a claims hook that throws, the family's end) must not burn it — a burnt token's
        // retry would look like reuse and revoke the whole family.
        const row = await peekRefreshRow(state, tokenHash);
        if (!row) {
            await handleRefreshReuse(state, tokenHash);
            throw new IdpError({ code: 'INVALID_REFRESH_TOKEN', httpStatus: 401, message: 'Invalid or expired refresh token' });
        }
        // An OAuth2 client's refresh token is redeemable only at /oauth2/token by that client — never
        // here, where it would mint a first-party session without client authentication. It is revoked
        // (not as a rotation), since a client token showing up here means it leaked.
        if (sessionKindOf(row) !== SESSION_KINDS.FIRST_PARTY) {
            await state.storage.sessionRepository.revokeByRefreshTokenHash(tokenHash, { reason: 'misused' });
            state.logger?.warn?.({ userId: String(row.user) }, 'OAuth2 refresh token presented at /refresh — refused and revoked');
            throw new IdpError({ code: 'INVALID_REFRESH_TOKEN', httpStatus: 401, message: 'Invalid or expired refresh token' });
        }

        // A full user, so resolveAuthContext gets the same shape of `user` as on every login path.
        const user = await state.storage.userRepository.findById(row.user);
        if (!isActiveAccount(user)) throw new IdpError({ code: 'USER_NOT_ACTIVE', httpStatus: 403, message: 'User account is not active' });

        // The family's absolute end applies however actively it's been refreshed.
        const { familyId, familyCreatedAt } = familyOf(row);
        if (familyEndsAt(state, familyCreatedAt) <= new Date()) {
            throw new IdpError({ code: 'INVALID_REFRESH_TOKEN', httpStatus: 401, message: 'Session has reached its maximum lifetime — please sign in again' });
        }

        const claims = state.config.session.reresolveClaimsOnRefresh
            ? await resolveClaims(state, user, { isNewUser: false, method: 'refresh' })
            : row.claims || {};

        // Now consume — atomically: of two concurrent refreshes with one token, only one gets here.
        const existing = await state.storage.sessionRepository.revokeByRefreshTokenHash(tokenHash, { reason: 'rotated' });
        if (!existing) {
            await handleRefreshReuse(state, tokenHash);
            throw new IdpError({ code: 'INVALID_REFRESH_TOKEN', httpStatus: 401, message: 'Invalid or expired refresh token' });
        }

        // A refresh is not an authentication: the original login time carries over (a row from
        // before 0.4.0 has none, which requireRecentAuth treats as "not recent").
        const authTime = existing.authTime ? Math.floor(new Date(existing.authTime).getTime() / 1000) : undefined;
        const accessToken = await issueAccessToken(state, { sub: String(user.id), email: user.email, claims }, { authTime });
        const newRefreshTokenValue = generateOpaqueToken();
        const newRefreshTokenHash = hashOpaqueToken(state, newRefreshTokenValue, HASH_PURPOSES.REFRESH_TOKEN);
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
            sessionEpoch: existing.sessionEpoch ?? 0,
            claims,
        });
        await assertChainNotRevoked(state, user.id, existing.sessionEpoch ?? 0, newRefreshTokenHash, familyId);
        await assertFamilyNotRevoked(state, familyId, newRefreshTokenHash);

        await state.cache.set(`${CACHE_KEY_PREFIXES.REVOKED_REFRESH_TOKEN}:${existing.jti}`, '1', state.config.ttls.revocationCache);

        await auditLog(state.logger, state.hooks, 'TOKEN_REFRESHED', { userId: String(user.id) });

        setSessionCookies(req, res, state, { accessToken, refreshTokenValue: newRefreshTokenValue, refreshExpiresAt });
        res.json({ accessToken: accessToken.token, accessTokenExpiresAt: accessToken.expiresAt, ...refreshTokenInBody(state, req, newRefreshTokenValue), refreshTokenExpiresAt: refreshExpiresAt });
    } catch (err) {
        next(err);
    }
}

export async function logoutHandler(req, res, next) {
    try {
        const state = getState();
        // Every browser request, body token or not: logout clears the session cookies, so a cross-site
        // form posting any token would otherwise sign the victim out (logout CSRF).
        assertTrustedOrigin(state, req);
        let refreshTokenValue;
        try {
            refreshTokenValue = req.body?.refreshToken || readRefreshCookie(state, req);
        } catch (err) {
            clearSessionCookies(req, res, state); // conflicting cookies (cookies.domain): still sign the browser out
            throw err;
        }
        if (!refreshTokenValue) {
            // Nothing usable to revoke (no cookie, or only one planted without its binding): the browser's
            // cookies are cleared all the same.
            clearSessionCookies(req, res, state);
            throw new IdpError({ code: 'REFRESH_TOKEN_REQUIRED', httpStatus: 400, message: 'Refresh token is required to log out' });
        }

        const tokenHash = await resolveRefreshTokenHash(state, refreshTokenValue);
        const existing = await state.storage.sessionRepository.revokeByRefreshTokenHash(tokenHash, { onlyIfActive: false });
        if (existing?.jti) {
            await state.cache.set(`${CACHE_KEY_PREFIXES.REVOKED_REFRESH_TOKEN}:${existing.jti}`, '1', state.config.ttls.revocationCache);
        }

        await auditLog(state.logger, state.hooks, 'LOGOUT', { userId: String(existing?.user ?? req.auth?.userId ?? 'unknown') });
        clearSessionCookies(req, res, state);
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

        // Enumeration-safe: the same answer at the same speed for every address.
        res.json({ status: 'ok' });
        runAfterResponse(state, 'Password-reset request', async () => {
            const user = await state.storage.userRepository.findByEmail(email);
            if (!user || user.status === IDENTITY_STATUS.DELETED) return;

            // Only the newest link works: requesting another replaces the earlier one (atomically, so
            // concurrent requests can't leave several live links).
            const resetToken = generateOpaqueToken(32);
            await state.storage.verificationTokenRepository.replaceForUser('password_reset', user.id, {
                tokenHash: hashOpaqueToken(state, resetToken, HASH_PURPOSES.PASSWORD_RESET),
                expiresAt: new Date(Date.now() + state.config.ttls.passwordReset * 1000),
            });

            invokeHookDetached(state.logger, state.hooks, 'onPasswordResetRequested', {
                email, resetToken, firstName: user.profile?.firstName, lastName: user.profile?.lastName,
            });
        });
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

        const { result: record } = await lookupByTokenHash(state, token, HASH_PURPOSES.PASSWORD_RESET, (hash) => state.storage.verificationTokenRepository.consumeByHash('password_reset', hash, user.id));
        if (!record) throw new IdpError({ code: 'INVALID_OR_EXPIRED_TOKEN', httpStatus: 400, message: 'Invalid or expired token' });

        const passwordHash = await hashPassword(newPassword, state.config.security.bcryptRounds);
        // Proving the inbox and setting a new password also lifts a lockout (the lock exists to stop
        // password guessing — the guessed password is gone).
        const changes = { passwordHash, passwordChangedAt: new Date(), failedLoginAttempts: 0, lockUntil: null };
        // On a never-verified account the reset is ALSO the verification — it proved the inbox, like a
        // magic link. Left pending, the account's outstanding verification code (bound to whichever
        // password registered it — possibly an attacker's pre-registration) would later activate THAT
        // password over the one just set.
        const activated = user.status === IDENTITY_STATUS.PENDING_VERIFICATION
            && await state.storage.userRepository.updateByIdIfStatus(record.user, IDENTITY_STATUS.PENDING_VERIFICATION, {
                ...changes, status: IDENTITY_STATUS.ACTIVE, registrationContested: false,
                mfaEnabled: false, mfaSecret: null, mfaTempSecret: null, mfaRecoveryCodes: [],
            });
        await state.attemptCounters.reset(passwordLoginKey(record.user));
        if (activated) {
            await state.storage.verificationTokenRepository.deleteAllForUser('email_verification', record.user);
        } else {
            // (Not an administrative lock — a LOCKED status without a lockUntil; see account-status.js.)
            const legacyLock = user.status === IDENTITY_STATUS.LOCKED && user.lockUntil ? { status: IDENTITY_STATUS.ACTIVE } : {};
            await state.storage.userRepository.updateById(record.user, { ...changes, ...legacyLock });
        }
        await revokeAllUserSessions(state, record.user);
        // Any other outstanding reset links die with this one.
        await state.storage.verificationTokenRepository.deleteAllForUser('password_reset', record.user);

        await auditLog(state.logger, state.hooks, 'PASSWORD_RESET', { userId: String(record.user) });
        res.json({ status: 'ok' });
    } catch (err) {
        next(err);
    }
}

const PASSWORD_CHANGE_LOCKED = () => new IdpError({ code: 'PASSWORD_CHANGE_LOCKED', httpStatus: 429, message: 'Too many wrong passwords — try again later, or reset your password by email.' });

export async function changePasswordHandler(req, res, next) {
    try {
        const state = getState();
        const userId = req.auth?.userId;
        if (!userId) throw new IdpError({ code: 'UNAUTHENTICATED', httpStatus: 401, message: 'Authentication required' });

        const { currentPassword, newPassword } = req.body;
        const user = await state.storage.userRepository.findById(userId, { select: '+passwordHash' });
        if (!user) throw new IdpError({ code: 'USER_NOT_FOUND', httpStatus: 404, message: 'User not found' });

        // Reached with a session, not a password: without a budget this is an unlimited password
        // oracle for whoever holds a stolen access token.
        await withAttemptBudget(state, `password-change:${userId}`, state.config.security.passwordChangeLockout, {
            lockedError: PASSWORD_CHANGE_LOCKED,
            isFailure: (err) => err?.code === 'CURRENT_PASSWORD_INCORRECT',
            onLocked: () => auditLog(state.logger, state.hooks, 'PASSWORD_CHANGE_LOCKED', { userId }),
        }, async () => {
            if (!(await verifyPassword(currentPassword, user.passwordHash))) {
                throw new IdpError({ code: 'CURRENT_PASSWORD_INCORRECT', httpStatus: 400, message: 'Current password is incorrect' });
            }
        });

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

        const user = await state.storage.userRepository.findById(req.auth.userId, { select: 'email status lockUntil mfaEnabled profile createdAt updatedAt' });
        if (!user) throw new IdpError({ code: 'USER_NOT_FOUND', httpStatus: 404, message: 'User not found' });

        res.json({
            userId: String(user.id),
            email: user.email,
            emailVerified: user.status !== IDENTITY_STATUS.PENDING_VERIFICATION,
            // (A pre-0.4.0 automatic lock reads as ACTIVE — see account-status.js.)
            isActive: isActiveAccount(user),
            status: effectiveStatus(user),
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
