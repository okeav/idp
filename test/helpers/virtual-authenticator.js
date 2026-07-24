import crypto from 'crypto';

/**
 * A minimal, hand-rolled "software authenticator" for exercising the full
 * WebAuthn ceremony end-to-end in tests, without a real browser or hardware
 * key. There's no official virtual-authenticator package from
 * @simplewebauthn — this implements just enough of the spec (attestation
 * format "none", ES256/P-256 credentials) to produce responses
 * @simplewebauthn/server's verifyRegistrationResponse /
 * verifyAuthenticationResponse will accept as genuine.
 *
 * This is test-only code — a hand-rolled CBOR encoder covering exactly the
 * fixed shapes WebAuthn "none" attestation needs (a 3-key text-string map
 * for the attestation object, a 5-key integer-keyed map for a COSE EC2
 * public key). Nowhere near a general CBOR implementation, and not meant
 * to be one.
 */

function cborHeader(majorType, length) {
    const mt = majorType << 5;
    if (length < 24) return Buffer.from([mt | length]);
    if (length < 256) return Buffer.from([mt | 24, length]);
    if (length < 65536) return Buffer.from([mt | 25, (length >> 8) & 0xff, length & 0xff]);
    throw new Error('virtual authenticator CBOR encoder: value too large for this minimal implementation');
}
const cborTextString = (str) => { const b = Buffer.from(str, 'utf8'); return Buffer.concat([cborHeader(3, b.length), b]); };
const cborByteString = (bytes) => Buffer.concat([cborHeader(2, bytes.length), Buffer.from(bytes)]);
const cborUint = (n) => cborHeader(0, n);
const cborNegInt = (n) => cborHeader(1, -1 - n);
const cborMapHeader = (numPairs) => cborHeader(5, numPairs);

function encodeCoseEC2PublicKey(x, y) {
    return Buffer.concat([
        cborMapHeader(5),
        cborUint(1), cborUint(2), // kty: EC2
        cborUint(3), cborNegInt(-7), // alg: ES256
        cborNegInt(-1), cborUint(1), // crv: P-256
        cborNegInt(-2), cborByteString(x), // x
        cborNegInt(-3), cborByteString(y), // y
    ]);
}

function encodeAttestationObjectNone(authData) {
    return Buffer.concat([
        cborMapHeader(3),
        cborTextString('fmt'), cborTextString('none'),
        cborTextString('attStmt'), cborMapHeader(0),
        cborTextString('authData'), cborByteString(authData),
    ]);
}

const b64url = (buf) => Buffer.from(buf).toString('base64url');

export function createVirtualAuthenticator({ rpID }) {
    const rpIdHash = crypto.createHash('sha256').update(rpID).digest();
    const credentials = new Map(); // credentialId (base64url) -> { privateKey, publicKey, counter }

    function buildAuthData({ counter, attestedCredentialData }) {
        const flags = attestedCredentialData ? 0b01000101 : 0b00000101; // UP+UV(+AT)
        const counterBuf = Buffer.alloc(4);
        counterBuf.writeUInt32BE(counter, 0);
        const parts = [rpIdHash, Buffer.from([flags]), counterBuf];
        if (attestedCredentialData) parts.push(attestedCredentialData);
        return Buffer.concat(parts);
    }

    return {
        /** Simulates navigator.credentials.create() against options from generateRegistrationOptions(). */
        createCredential(options, { origin }) {
            const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
            const jwk = publicKey.export({ format: 'jwk' });
            const publicKeyCose = encodeCoseEC2PublicKey(Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url'));

            const credentialId = crypto.randomBytes(32);
            const credentialIdB64 = b64url(credentialId);

            const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.create', challenge: options.challenge, origin, crossOrigin: false }), 'utf8');

            const aaguid = Buffer.alloc(16);
            const credIdLen = Buffer.alloc(2);
            credIdLen.writeUInt16BE(credentialId.length, 0);
            const attestedCredentialData = Buffer.concat([aaguid, credIdLen, credentialId, publicKeyCose]);
            const authData = buildAuthData({ counter: 0, attestedCredentialData });
            const attestationObject = encodeAttestationObjectNone(authData);

            credentials.set(credentialIdB64, { privateKey, publicKey, counter: 0 });

            return {
                id: credentialIdB64,
                rawId: credentialIdB64,
                type: 'public-key',
                clientExtensionResults: {},
                response: {
                    clientDataJSON: b64url(clientDataJSON),
                    attestationObject: b64url(attestationObject),
                    transports: ['internal'],
                },
            };
        },

        /** Simulates navigator.credentials.get() against options from generateAuthenticationOptions(). Defaults to the most recently registered credential. */
        getAssertion(options, { origin, credentialId } = {}) {
            const id = credentialId || [...credentials.keys()].at(-1);
            const stored = credentials.get(id);
            if (!stored) throw new Error('virtual authenticator: unknown credential');

            stored.counter += 1;

            const clientDataJSON = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: options.challenge, origin, crossOrigin: false }), 'utf8');
            const clientDataHash = crypto.createHash('sha256').update(clientDataJSON).digest();
            const authData = buildAuthData({ counter: stored.counter, attestedCredentialData: null });
            const signature = crypto.sign('sha256', Buffer.concat([authData, clientDataHash]), stored.privateKey);

            return {
                id,
                rawId: id,
                type: 'public-key',
                clientExtensionResults: {},
                response: {
                    clientDataJSON: b64url(clientDataJSON),
                    authenticatorData: b64url(authData),
                    signature: b64url(signature),
                },
            };
        },
    };
}
