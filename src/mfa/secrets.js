import { getState } from '../config/state.js';
import { IdpError } from '../errors/idp-error.js';
import { AesGcmSecretCipher } from './secret-cipher.js';

// otplib's generateSecret() emits RFC 4648 base32. Anything of that shape is
// a secret written before encryption at rest existed (≤0.2.x); everything
// else is ciphertext. The built-in format always contains ':', which base32
// never does.
const PLAINTEXT_SECRET = /^[A-Z2-7]+=*$/i;

export function isPlaintextMfaSecret(value) {
    return typeof value === 'string' && PLAINTEXT_SECRET.test(value);
}

/** `config.mfa.secretCipher` wins; otherwise `encryptionKey` builds the AES-256-GCM cipher; otherwise null. */
export function createMfaSecretCipher(mfaConfig = {}) {
    if (mfaConfig.secretCipher) {
        const c = mfaConfig.secretCipher;
        if (typeof c.encrypt !== 'function' || typeof c.decrypt !== 'function') {
            throw new Error('config.mfa.secretCipher must implement encrypt(plaintext, { context }) and decrypt(ciphertext, { context })');
        }
        return c;
    }
    if (mfaConfig.encryptionKey) {
        return new AesGcmSecretCipher({ currentKey: mfaConfig.encryptionKey, previousKeys: mfaConfig.previousEncryptionKeys || [] });
    }
    return null;
}

/**
 * Startup validation — called from initIdentityProvider(). MFA is on by
 * default, so a deployment that never set a key fails here, on boot, rather
 * than silently writing TOTP secrets in plain text.
 */
export function assertMfaSecretConfig(mfaConfig, cipher, logger) {
    if (mfaConfig.requireEncrypted && !cipher) {
        throw new Error('config.mfa.requireEncrypted is set but no config.mfa.encryptionKey or config.mfa.secretCipher is configured');
    }
    if (!mfaConfig.enabled || cipher) return;
    if (!mfaConfig.allowPlaintext) {
        throw new Error(
            'MFA secrets must be encrypted at rest: set config.mfa.encryptionKey (32 bytes, base64 — `openssl rand -base64 32`) ' +
            'or config.mfa.secretCipher. For local development only, config.mfa.allowPlaintext: true opts out. ' +
            'If this deployment does not use TOTP MFA at all, set config.mfa.enabled: false.'
        );
    }
    logger?.warn?.(
        {},
        '!!! @okeav/idp-core: config.mfa.allowPlaintext is ON — TOTP secrets are being stored UNENCRYPTED. ' +
        'Development use only. Set config.mfa.encryptionKey before deploying anywhere real. !!!'
    );
}

/** Encrypts a TOTP secret for storage. Plain text only when the app explicitly opted into `allowPlaintext` and has no key. */
export async function sealMfaSecret(state, plaintext, userId) {
    if (state.mfaCipher) return state.mfaCipher.encrypt(plaintext, { context: String(userId) });
    if (state.config.mfa.allowPlaintext) return plaintext;
    throw new IdpError({ code: 'MFA_ENCRYPTION_NOT_CONFIGURED', httpStatus: 500, message: 'MFA secret encryption is not configured' });
}

/**
 * Reads a stored TOTP secret. Fails closed: undecryptable ciphertext (tampered,
 * wrong key, copied from another user) throws rather than being treated as
 * "no secret". `needsUpgrade` is true for a legacy plain-text value (or one
 * under a retired key) that the caller should re-seal after a successful verify.
 *
 * @returns {Promise<{ secret: string, needsUpgrade: boolean } | null>}
 */
export async function openMfaSecret(state, stored, userId) {
    if (!stored) return null;
    const cipher = state.mfaCipher;

    if (isPlaintextMfaSecret(stored)) {
        if (state.config.mfa.requireEncrypted) {
            state.logger?.error?.({ userId: String(userId) }, 'Refusing a plain-text MFA secret (config.mfa.requireEncrypted is set) — run migrateMfaSecrets()');
            throw new IdpError({ code: 'MFA_SECRET_NOT_ENCRYPTED', httpStatus: 500, message: 'MFA secret is not encrypted' });
        }
        return { secret: stored, needsUpgrade: Boolean(cipher) };
    }

    if (!cipher) {
        throw new IdpError({ code: 'MFA_ENCRYPTION_NOT_CONFIGURED', httpStatus: 500, message: 'MFA secret is encrypted but no key is configured' });
    }
    let secret;
    try {
        secret = await cipher.decrypt(stored, { context: String(userId) });
    } catch (cause) {
        state.logger?.error?.({ userId: String(userId), err: cause }, 'Failed to decrypt MFA secret — tampered, wrong key, or key id not configured');
        throw new IdpError({ code: 'MFA_SECRET_UNREADABLE', httpStatus: 500, message: 'Unable to read MFA secret', cause });
    }
    return { secret, needsUpgrade: typeof cipher.needsRotation === 'function' && cipher.needsRotation(stored) === true };
}

/**
 * Encrypts every plain-text `mfaSecret`/`mfaTempSecret` in one pass, and
 * re-encrypts any written under a non-current key. Idempotent and safe to
 * run while the app is serving traffic (a concurrent lazy re-encryption
 * writes an equivalent value). Users created during the run are already
 * written encrypted, so a page that shifts under it skips nothing that matters.
 *
 * Works with any storage adapter: it only uses `countAll`, `findMany`,
 * `findById` and `updateById`.
 *
 * @param {{ batchSize?: number, dryRun?: boolean }} [opts]
 * @returns {Promise<{ scanned: number, encrypted: number, reencrypted: number, failed: Array<{ userId: string, error: string }> }>}
 */
export async function migrateMfaSecrets({ batchSize = 100, dryRun = false } = {}) {
    const state = getState();
    const cipher = state.mfaCipher;
    if (!cipher) throw new Error('migrateMfaSecrets() needs config.mfa.encryptionKey or config.mfa.secretCipher');
    const repo = state.storage.userRepository;

    const total = await repo.countAll();
    const ids = new Set();
    for (let skip = 0; skip < total; skip += batchSize) {
        const page = await repo.findMany({ skip, limit: batchSize });
        if (!page.length) break;
        for (const u of page) ids.add(String(u.id ?? u._id));
    }

    const result = { scanned: 0, encrypted: 0, reencrypted: 0, failed: [] };
    for (const userId of ids) {
        result.scanned += 1;
        try {
            const user = await repo.findById(userId, { select: '+mfaSecret +mfaTempSecret' });
            if (!user) continue;
            const patch = {};
            for (const field of ['mfaSecret', 'mfaTempSecret']) {
                const stored = user[field];
                if (!stored) continue;
                if (isPlaintextMfaSecret(stored)) {
                    patch[field] = await cipher.encrypt(stored, { context: userId });
                    result.encrypted += 1;
                } else if (typeof cipher.needsRotation === 'function' && cipher.needsRotation(stored)) {
                    const plaintext = await cipher.decrypt(stored, { context: userId });
                    patch[field] = await cipher.encrypt(plaintext, { context: userId });
                    result.reencrypted += 1;
                }
            }
            if (!dryRun && Object.keys(patch).length > 0) await repo.updateById(userId, patch);
        } catch (err) {
            result.failed.push({ userId, error: err.message });
        }
    }

    state.logger?.info?.({ ...result, failed: result.failed.length, dryRun }, 'migrateMfaSecrets finished');
    return result;
}
