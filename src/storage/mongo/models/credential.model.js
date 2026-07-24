import mongoose from 'mongoose';
import { mongoIdPlugin } from '../plugins/mongo-id.plugin.js';

/**
 * A registered WebAuthn/passkey authenticator. `credentialId` (base64url,
 * globally unique per the WebAuthn spec) is the primary lookup key — it's
 * how an incoming assertion response gets matched back to a user without
 * already knowing who's authenticating (the primary-passwordless-login
 * case). `publicKey` is stored as base64 (raw COSE-key bytes); `counter` is
 * the signature counter used for clone/replay detection, updated after
 * every successful authentication.
 */
export function defineCredentialModel(connection) {
    const schema = new mongoose.Schema(
        {
            user: { type: mongoose.Schema.Types.ObjectId, ref: 'IdpIdentityUser', required: true },
            credentialId: { type: String, required: true, unique: true, index: true },
            publicKey: { type: String, required: true }, // base64
            counter: { type: Number, required: true, default: 0 },
            transports: { type: [String], default: [] },
            deviceType: { type: String, enum: ['singleDevice', 'multiDevice'], default: 'singleDevice' },
            backedUp: { type: Boolean, default: false },
            name: { type: String, default: null }, // consumer-facing friendly label, e.g. "MacBook Touch ID"
            lastUsedAt: { type: Date, default: null },
        },
        { timestamps: true }
    );

    schema.index({ user: 1 });

    schema.plugin(mongoIdPlugin);

    return connection.model('IdpCredential', schema);
}
