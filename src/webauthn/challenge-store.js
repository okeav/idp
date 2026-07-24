import { CACHE_KEY_PREFIXES } from '../config/constants.js';

/**
 * Ephemeral, single-use storage for the challenge issued by
 * generateRegistrationOptions/generateAuthenticationOptions, keyed by
 * whatever identifies this specific ceremony (a userId for registration and
 * MFA-scoped authentication; a random per-attempt id for usernameless
 * primary-login authentication, carried to the client alongside the
 * options and echoed back with the assertion response).
 */
export async function storeChallenge(state, key, challenge) {
    await state.cache.set(`${CACHE_KEY_PREFIXES.WEBAUTHN_CHALLENGE}:${key}`, challenge, state.config.ttls.webauthnChallenge);
}

export async function consumeChallenge(state, key) {
    const cacheKey = `${CACHE_KEY_PREFIXES.WEBAUTHN_CHALLENGE}:${key}`;
    const challenge = await state.cache.get(cacheKey);
    if (challenge) await state.cache.del(cacheKey);
    return challenge ?? null;
}
