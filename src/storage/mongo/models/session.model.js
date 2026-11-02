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
            // Set on EVERY row of a family revoked as a whole (reuse detected) — a tombstone a refresh that
            // was already in flight checks after inserting its successor (see assertFamilyNotRevoked).
            familyRevokedAt: { type: Date, default: null },
            deviceInfo: { type: String },
            deviceFingerprint: { type: String, default: null, index: true },
            ipAddress: { type: String },

            // 'first_party' (this IdP's own login) or 'oauth2' (an OAuth2 client's grant — `claims.clientId`
            // names the client). A refresh token is only ever redeemable where it was issued. Null on
            // rows written before 0.4.0; see utils/session-kind.js for how those are classified.
            kind: { type: String, enum: ['first_party', 'oauth2', null], default: null },

            // When the user authenticated to create this session chain (first-party only). Copied
            // across refresh rotations; becomes the access token's `auth_time`.
            authTime: { type: Date, default: null },

            // Refresh-token family: every row produced by rotating one login's (or one authorization
            // code's) refresh token shares a familyId. Presenting an already-rotated token revokes the
            // whole family (theft detection); familyCreatedAt bounds the family's absolute lifetime.
            familyId: { type: String, default: null },
            familyCreatedAt: { type: Date, default: null },
            // The user's `sessionEpoch` when this chain was authenticated (see identity-user.model.js).
            sessionEpoch: { type: Number, default: 0 },

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
    schema.index({ familyId: 1, revokedAt: 1 }, { sparse: true });
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
