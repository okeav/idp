import { CACHE_KEY_PREFIXES } from '../config/constants.js';

/**
 * Ephemeral, single-use storage for the challenge issued by
 * generateRegistrationOptions/generateAuthenticationOptions, keyed by
 * whatever identifies this specific ceremony (a userId for registration and
 * MFA-scoped authentication; the challenge value itself for usernameless
 * primary-login authentication).
 */
export async function storeChallenge(state, key, challenge) {
    await state.cache.set(`${CACHE_KEY_PREFIXES.WEBAUTHN_CHALLENGE}:${key}`, challenge, state.config.ttls.webauthnChallenge);
}

/** Atomic get-and-delete (`cache.take`): two concurrent verifies can never both redeem one challenge. */
export async function consumeChallenge(state, key) {
    return (await state.cache.take(`${CACHE_KEY_PREFIXES.WEBAUTHN_CHALLENGE}:${key}`)) ?? null;
}
