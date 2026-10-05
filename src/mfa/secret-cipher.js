import crypto from 'crypto';

const FORMAT_VERSION = 'v1';
const KEY_ID_PATTERN = /^[A-Za-z0-9_-]{1,64}$/;
const IV_BYTES = 12; // 96-bit nonce — the GCM-recommended size
const TAG_BYTES = 16;

/**
 * @typedef {Object} SecretCipher
 * Pluggable at-rest encryption for TOTP secrets (`mfaSecret`/`mfaTempSecret`).
 * Supply your own via `config.mfa.secretCipher` to route through a KMS/HSM;
 * otherwise `config.mfa.encryptionKey` builds the built-in AES-256-GCM one.
 *
 * Whatever `encrypt` returns is stored verbatim. It must NOT look like a bare
 * base32 string (`/^[A-Z2-7]+=*$/i`) — that shape is how a not-yet-migrated
 * plain-text secret is recognised (see secrets.js). A prefix such as `kms:`
 * is enough.
 *
 * `context` is the owning user's id. Bind it to the ciphertext (the built-in
 * cipher uses it as GCM additional authenticated data) so an encrypted
 * secret copied onto another user's row fails to decrypt.
 *
 * @property {(plaintext: string, opts: { context: string }) => string | Promise<string>} encrypt
 * @property {(ciphertext: string, opts: { context: string }) => string | Promise<string>} decrypt
 * @property {(ciphertext: string) => boolean} [needsRotation] - true when `ciphertext` was written under a key that's no longer current; triggers re-encryption on the next successful verify
 */

/**
 * Built-in AES-256-GCM cipher. Stored format:
 * `v1:<keyId>:<iv>:<ciphertext>:<tag>` (each binary part base64url).
 *
 * Rotation: encryption always uses `currentKey`; decryption accepts any key
 * whose id appears in `currentKey` or `previousKeys`. Move the old key into
 * `previousKeys`, set the new one as current, and either let secrets
 * re-encrypt lazily on each user's next successful verify or run
 * `migrateMfaSecrets()` to do them all at once.
 */
export class AesGcmSecretCipher {
    /**
     * @param {{ currentKey: string | { id?: string, key: string }, previousKeys?: Array<string | { id?: string, key: string }> }} opts
     *   Each key is 32 bytes, base64-encoded. A bare string's id is derived
     *   from a SHA-256 fingerprint of the key, so a single-key setup needs no
     *   id at all; pass `{ id, key }` to name keys explicitly.
     */
    constructor({ currentKey, previousKeys = [] } = {}) {
        if (!currentKey) throw new Error('AesGcmSecretCipher requires currentKey');
        const current = normalizeKey(currentKey);
        this._currentId = current.id;
        this._keys = new Map([[current.id, current.key]]);
        for (const entry of previousKeys) {
            const { id, key } = normalizeKey(entry);
            if (this._keys.has(id) && !this._keys.get(id).equals(key)) {
                throw new Error(`MFA encryption key id "${id}" is configured twice with different key material`);
            }
            this._keys.set(id, key);
        }
    }

    get currentKeyId() {
        return this._currentId;
    }

    encrypt(plaintext, { context = '' } = {}) {
        const iv = crypto.randomBytes(IV_BYTES);
        const cipher = crypto.createCipheriv('aes-256-gcm', this._keys.get(this._currentId), iv, { authTagLength: TAG_BYTES });
        cipher.setAAD(aad(context));
        const ciphertext = Buffer.concat([cipher.update(String(plaintext), 'utf8'), cipher.final()]);
        const tag = cipher.getAuthTag();
        return [FORMAT_VERSION, this._currentId, b64u(iv), b64u(ciphertext), b64u(tag)].join(':');
    }

    decrypt(stored, { context = '' } = {}) {
        const { keyId, iv, ciphertext, tag } = parseStored(stored);
        const key = this._keys.get(keyId);
        if (!key) throw new Error(`No MFA encryption key configured for key id "${keyId}"`);
        const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv, { authTagLength: TAG_BYTES });
        decipher.setAAD(aad(context));
        decipher.setAuthTag(tag);
        // final() throws on any tag mismatch — tampered ciphertext, wrong key
        // material under a known id, or a different user's context all fail here.
        return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
    }

    needsRotation(stored) {
        try {
            return parseStored(stored).keyId !== this._currentId;
        } catch {
            return false;
        }
    }
}

/** Fingerprint-derived id for a key given without one — stable, short, and reveals nothing usable about a random 256-bit key. */
export function deriveKeyId(keyBuffer) {
    return crypto.createHash('sha256').update(keyBuffer).digest('hex').slice(0, 12);
}

function normalizeKey(entry) {
    const raw = typeof entry === 'string' ? entry : entry?.key;
    if (typeof raw !== 'string' || raw.length === 0) throw new Error('MFA encryption key must be a base64-encoded string');
    const key = Buffer.from(raw, 'base64');
    if (key.length !== 32) {
        throw new Error(`MFA encryption key must decode to exactly 32 bytes (got ${key.length}) — generate one with \`openssl rand -base64 32\``);
    }
    const id = typeof entry === 'object' && entry.id ? entry.id : deriveKeyId(key);
    if (!KEY_ID_PATTERN.test(id)) throw new Error(`MFA encryption key id "${id}" must match ${KEY_ID_PATTERN}`);
    return { id, key };
}

function parseStored(stored) {
    const parts = typeof stored === 'string' ? stored.split(':') : [];
    if (parts.length !== 5 || parts[0] !== FORMAT_VERSION) throw new Error('Unrecognised encrypted MFA secret format');
    const [, keyId, iv, ciphertext, tag] = parts;
    return { keyId, iv: fromB64u(iv), ciphertext: fromB64u(ciphertext), tag: fromB64u(tag) };
}

function aad(context) {
    return Buffer.from(`idp-mfa-secret:${context}`, 'utf8');
}

function b64u(buf) {
    return buf.toString('base64url');
}

function fromB64u(str) {
    return Buffer.from(str, 'base64url');
}
