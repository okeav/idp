import crypto from 'crypto';
import { IdpError } from '../errors/idp-error.js';
import { CACHE_KEY_PREFIXES } from '../config/constants.js';
import { auditLog } from '../hooks/index.js';

/**
 * Refresh-token families (RFC 9700 §4.14.2). A login — or an OAuth2 authorization code — starts a
 * family; each rotation adds a row to it. Rows record why they were revoked, so presenting a refresh
 * token that was already *rotated* is recognisable: someone holds a copy. The legitimate client and
 * the thief each have a token of the same family, and only one of them can be the rightful one —
 * so the whole family is revoked and both must log in again.
 */

export const newFamilyId = () => crypto.randomUUID();

/** The family a row belongs to. Rows from before 0.4.0 have none: each starts its own from here on. */
export function familyOf(session) {
    return {
        familyId: session.familyId ?? `legacy:${session.id ?? session._id}`,
        familyCreatedAt: session.familyCreatedAt ?? session.authTime ?? session.createdAt ?? new Date(),
    };
}

/** When a family must end regardless of activity (`session.absoluteLifetimeSeconds`). */
export function familyEndsAt(state, familyCreatedAt) {
    return new Date(new Date(familyCreatedAt).getTime() + state.config.session.absoluteLifetimeSeconds * 1000);
}

/** A refresh row's expiry: the usual sliding TTL, but never past the family's absolute end. */
export function cappedExpiry(state, familyCreatedAt, ttlSeconds) {
    const sliding = new Date(Date.now() + ttlSeconds * 1000);
    const end = familyEndsAt(state, familyCreatedAt);
    return sliding < end ? sliding : end;
}

async function markRevokedInCache(state, jtis) {
    for (const jti of jtis || []) {
        await state.cache.set(`${CACHE_KEY_PREFIXES.REVOKED_REFRESH_TOKEN}:${jti}`, '1', state.config.ttls.revocationCache);
    }
}

/**
 * The live (unrevoked, unexpired) row for a refresh token, read WITHOUT consuming it — so a refresh
 * can run every check before it commits. The consume that follows is still the atomic gate.
 */
export async function peekRefreshRow(state, tokenHash) {
    const row = await state.storage.sessionRepository.findByRefreshTokenHash(tokenHash);
    if (!row || row.revokedAt || !(new Date(row.expiresAt) > new Date())) return null;
    return row;
}

/**
 * Called when a refresh token didn't redeem. If it is one that was already rotated — and not within
 * the short `session.refreshReuseGraceSeconds` (two tabs refreshing at once) — revokes its family.
 */
export async function handleRefreshReuse(state, tokenHash) {
    const sessions = state.storage.sessionRepository;
    if (typeof sessions.revokeFamily !== 'function') return;
    const row = await sessions.findByRefreshTokenHash(tokenHash);
    if (!row?.revokedAt || row.revokeReason !== 'rotated') return;
    if (Date.now() - new Date(row.revokedAt).getTime() < state.config.session.refreshReuseGraceSeconds * 1000) return;

    const { familyId } = familyOf(row);
    const { revokedCount, jtis } = await sessions.revokeFamily(familyId, { reason: 'reuse_detected' });
    await markRevokedInCache(state, jtis);
    await auditLog(state.logger, state.hooks, 'REFRESH_TOKEN_REUSE_DETECTED', {
        userId: String(row.user), clientId: row.claims?.clientId ?? null, revokedSessions: revokedCount,
    });
}

/** Revokes a family outright (e.g. every token produced from a reused authorization code). */
export async function revokeFamily(state, familyId, reason) {
    const sessions = state.storage.sessionRepository;
    if (typeof sessions.revokeFamily !== 'function') return 0;
    const { revokedCount, jtis } = await sessions.revokeFamily(familyId, { reason });
    await markRevokedInCache(state, jtis);
    return revokedCount;
}

/**
 * "Revoke all of this user's sessions" (logout-all, password reset/change, account deletion). The
 * user's `sessionsRevokedAt` is written FIRST, then the rows are revoked: a refresh that consumed
 * its row just before and inserts its successor just after would otherwise leave that successor
 * alive. `assertChainNotRevoked` is the refresh-side half of that.
 */
export async function revokeAllUserSessions(state, userId, opts) {
    await state.storage.userRepository.updateById(userId, { sessionsRevokedAt: new Date(), sessionsRevokedExceptFamily: null });
    return state.storage.sessionRepository.revokeAllForUser(userId, opts);
}

/**
 * "Sign out every OTHER session" (MFA enrolment): the same watermark as revokeAllUserSessions, with the
 * current session's family exempt — so a refresh of another session that was already in flight is
 * still caught by assertChainNotRevoked, while the current session carries on.
 */
export async function revokeOtherUserSessions(state, userId, { exceptJti }) {
    const current = exceptJti && typeof state.storage.sessionRepository.findByJti === 'function'
        ? await state.storage.sessionRepository.findByJti(exceptJti)
        : null;
    const exceptFamily = current ? familyOf(current).familyId : null;
    await state.storage.userRepository.updateById(userId, { sessionsRevokedAt: new Date(), sessionsRevokedExceptFamily: exceptFamily });
    return state.storage.sessionRepository.revokeAllForUser(userId, { exceptJti });
}

/**
 * After a session row has been written (login, refresh): if every session of the user was revoked at
 * or after `since` — when the redeemed row was created, or when the login began checking credentials —
 * the new row belongs to a revoked chain: revoke it and refuse. `familyId` is spared only when it is
 * the family exempted by revokeOtherUserSessions.
 */
export async function assertChainNotRevoked(state, userId, since, newTokenHash, familyId) {
    const user = await state.storage.userRepository.findById(userId, { select: 'sessionsRevokedAt sessionsRevokedExceptFamily' });
    const revokedAt = user?.sessionsRevokedAt ? new Date(user.sessionsRevokedAt) : null;
    const exempt = familyId && user?.sessionsRevokedExceptFamily && user.sessionsRevokedExceptFamily === familyId;
    if (revokedAt && since && revokedAt >= new Date(since) && !exempt) {
        await state.storage.sessionRepository.revokeByRefreshTokenHash(newTokenHash, { onlyIfActive: false });
        throw new IdpError({ code: 'TOKEN_REVOKED', httpStatus: 401, message: 'Session has been revoked' });
    }
}

/**
 * After a refresh has written its successor: if reuse detection revoked the family meanwhile (it ran
 * while this refresh was between consuming its token and inserting the successor, so it couldn't see
 * the successor), revoke the successor and refuse.
 */
export async function assertFamilyNotRevoked(state, familyId, newTokenHash) {
    if (!(await state.storage.sessionRepository.isFamilyRevoked(familyId))) return;
    await state.storage.sessionRepository.revokeByRefreshTokenHash(newTokenHash, { onlyIfActive: false });
    throw new IdpError({ code: 'TOKEN_REVOKED', httpStatus: 401, message: 'Session has been revoked' });
}
