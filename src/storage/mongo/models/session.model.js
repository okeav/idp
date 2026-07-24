import mongoose from 'mongoose';
import { mongoIdPlugin } from '../plugins/mongo-id.plugin.js';

/**
 * A "session" = one refresh-token record. This is the authoritative
 * revocation state — `revokedAt` is checked on every refresh/verify;
 * the cache adapter's revocation cache is a fast-path in front of it.
 */
export function defineSessionModel(connection) {
    const schema = new mongoose.Schema(
        {
            user: { type: mongoose.Schema.Types.ObjectId, ref: 'IdpIdentityUser', required: true, index: true },
            tokenHash: { type: String, required: true, index: true },
            expiresAt: { type: Date, required: true },
            kid: { type: String, required: true },
            jti: { type: String, required: true },
            revokedAt: { type: Date, default: null },
            revokeReason: { type: String },
            deviceInfo: { type: String },
            deviceFingerprint: { type: String, default: null, index: true },
            ipAddress: { type: String },

            // Opaque snapshot of whatever the consumer put in the access token's
            // `claims` at the time this session was created — carried here so a
            // refresh can re-mint an access token without an outbound call back
            // to the consumer's own resolveAuthContext logic.
            claims: { type: mongoose.Schema.Types.Mixed, default: {} },
        },
        { timestamps: true }
    );

    // TTL cleanup is a MongoDB-native mechanism specific to this adapter — see
    // storage/interfaces.js for how a non-TTL-native adapter would implement
    // pruneExpired() instead.
    schema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
    schema.index({ tokenHash: 1, revokedAt: 1 });
    schema.index({ user: 1, revokedAt: 1, expiresAt: 1 });
    schema.index({ jti: 1 }, { sparse: true });
    schema.index({ user: 1, deviceFingerprint: 1 }, { sparse: true });

    schema.plugin(mongoIdPlugin);

    return connection.model('IdpSession', schema);
}

/** Optional, write-only audit trail of issued access tokens. Never read back for authorization decisions. */
export function defineAccessTokenAuditModel(connection) {
    const schema = new mongoose.Schema(
        {
            user: { type: mongoose.Schema.Types.ObjectId, ref: 'IdpIdentityUser', required: true, index: true },
            tokenHash: { type: String, required: true, index: true },
            expiresAt: { type: Date, required: true },
            kid: { type: String, required: true },
            jti: { type: String, required: true },
            ipAddress: { type: String },
            deviceInfo: { type: String },
        },
        { timestamps: true }
    );

    schema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
    schema.plugin(mongoIdPlugin);

    return connection.model('IdpAccessTokenAudit', schema);
}
