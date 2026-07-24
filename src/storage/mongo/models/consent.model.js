import mongoose from 'mongoose';
import { mongoIdPlugin } from '../plugins/mongo-id.plugin.js';

export function defineConsentModel(connection) {
    const schema = new mongoose.Schema(
        {
            userId: { type: mongoose.Schema.Types.ObjectId, ref: 'IdpIdentityUser', required: true, index: true },
            clientId: { type: String, required: true, index: true },
            scopes: [{ type: String }],
            grantedAt: { type: Date, default: Date.now },
            expiresAt: { type: Date, default: null },
            revokedAt: { type: Date, default: null },
            isRevoked: { type: Boolean, default: false },
        },
        { timestamps: true }
    );

    schema.index({ userId: 1, clientId: 1 }, { unique: true });
    schema.index({ userId: 1, isRevoked: 1 });
    schema.plugin(mongoIdPlugin);

    return connection.model('IdpConsent', schema);
}
