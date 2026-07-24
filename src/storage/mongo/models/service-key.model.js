import mongoose from 'mongoose';
import { KEY_STATUS } from '../../../config/constants.js';

/**
 * Public half of a participating service's S2S signing keypair — the
 * service-mesh JWKS trust registry (kept in scope as a differentiator
 * feature). `name` is an open string (any consumer-chosen service name),
 * not a closed enum — the audited version restricted this to Okeav's own
 * fixed SERVICE_NAMES list, which doesn't generalize.
 */
export function defineServiceKeyModel(connection) {
    const schema = new mongoose.Schema(
        {
            name: { type: String, required: true, index: true },
            kid: { type: String, required: true, unique: true, index: true },
            publicKey: { type: String, required: true }, // base64-encoded PEM
            status: { type: String, enum: Object.values(KEY_STATUS), default: KEY_STATUS.ACTIVE, index: true },
            region: { type: String, default: 'global' },
            registeredAt: { type: Date, default: () => new Date() },
            lastSeenAt: { type: Date, default: () => new Date() },
        },
        { timestamps: true, versionKey: false }
    );

    schema.index({ name: 1, status: 1 });

    return connection.model('IdpServiceKey', schema);
}
