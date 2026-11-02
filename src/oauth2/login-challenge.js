import crypto from 'crypto';
import { z } from 'zod';
import { familyOf } from '../utils/session-family.js';

/**
 * Login challenges: what makes `prompt=login` and `max_age` mean "a login for THIS request".
 *
 * When /oauth2/authorize needs a (new) login, it answers with a single-use `login_challenge`. The IdP's
 * frontend passes it to whichever sign-in it runs (password, magic link, passkey, SSO — and through
 * the MFA step, inside the challenge token), and the session that sign-in creates is bound to it. The
 * repeated authorize request presents the challenge, and is accepted only from exactly that session.
 * No time window, no clock: an earlier login, however recent, doesn't satisfy it.
 */

export const LOGIN_CHALLENGE_TTL_SECONDS = 15 * 60;
const key = (id) => `oauth2:login-challenge:${id}`;

/** The shape of a challenge id — for request schemas. */
export const loginChallengeSchema = z.string().regex(/^[A-Za-z0-9_-]{43}$/, 'login_challenge is malformed');
const isChallengeId = (v) => loginChallengeSchema.safeParse(v).success;

/** A new challenge for an authorization request of `clientId`. */
export async function createLoginChallenge(state, clientId) {
    const id = crypto.randomBytes(32).toString('base64url');
    await state.cache.set(key(id), { clientId, familyId: null }, LOGIN_CHALLENGE_TTL_SECONDS);
    return id;
}

/** Called once a sign-in has created its session: binds the challenge (if any, and not yet bound) to it. */
export async function bindLoginChallenge(state, id, familyId) {
    if (!id || !isChallengeId(id) || !familyId) return;
    const entry = await state.cache.get(key(id));
    if (!entry || entry.familyId) return; // unknown, expired, or already bound to another sign-in
    await state.cache.set(key(id), { ...entry, familyId }, LOGIN_CHALLENGE_TTL_SECONDS);
}

/**
 * Whether the request's session is the one bound to challenge `id` for `clientId` — consuming the
 * challenge if so (single use).
 */
export async function redeemLoginChallenge(state, req, id, clientId) {
    if (!id || !isChallengeId(id) || !req.auth?.userId || req.auth.tokenMeta?.sessionless) return false;
    const entry = await state.cache.get(key(id));
    if (!entry?.familyId || entry.clientId !== clientId) return false;
    const sessions = state.storage.sessionRepository;
    if (typeof sessions.findByJti !== 'function' || !req.auth.tokenMeta?.jti) return false;
    const row = await sessions.findByJti(req.auth.tokenMeta.jti);
    if (!row || row.revokedAt || String(row.user) !== String(req.auth.userId) || familyOf(row).familyId !== entry.familyId) return false;
    return Boolean(await state.cache.take(key(id)));
}
