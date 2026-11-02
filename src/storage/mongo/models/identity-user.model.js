import mongoose from 'mongoose';
import { mongoIdPlugin } from '../plugins/mongo-id.plugin.js';
import { IDENTITY_STATUS } from '../../../config/constants.js';

/**
 * @param {import('mongoose').Connection} connection
 * @param {{ hashEmail: (email: string) => string }} deps - blind-index hasher, injected
 *   so this model file has no direct dependency on the email-hash secret.
 */
export function defineIdentityUserModel(connection, { hashEmail }) {
    const schema = new mongoose.Schema(
        {
            email: { type: String, required: true, lowercase: true, trim: true },
            emailHash: { type: String, unique: true, sparse: true, index: true },
            passwordHash: { type: String, select: false },

            status: { type: String, enum: Object.values(IDENTITY_STATUS), default: IDENTITY_STATUS.PENDING_VERIFICATION },
            lastLoginAt: { type: Date },
            passwordChangedAt: { type: Date },
            // Incremented (before the rows are revoked) by every "revoke all of this user's sessions". Each
            // session row records the epoch its chain was authenticated in; a login or refresh racing a
            // revocation re-checks it, so it can't leave a session alive. A counter, not a time: the
            // comparison doesn't depend on the app servers' clocks agreeing.
            sessionEpoch: { type: Number, default: 0 },
            // When the last such revocation happened (informational).
            sessionsRevokedAt: { type: Date, default: null },
            // The one family exempt from the latest epoch bump (the session that enrolled MFA and signed out the others).
            sessionsRevokedExceptFamily: { type: String, default: null },
            // Set when a still-unverified address is registered again: verifying then needs the password
            // bound to the code (see registerHandler).
            registrationContested: { type: Boolean, default: false },
            failedLoginAttempts: { type: Number, default: 0 },
            lockUntil: { type: Date, default: null },

            mfaEnabled: { type: Boolean, default: false },
            mfaSecret: { type: String, select: false },
            mfaTempSecret: { type: String, select: false },
            // The last TOTP time step accepted for this account — a code is never accepted twice.
            mfaLastTotpStep: { type: Number, default: null, select: false },
            mfaRecoveryCodes: {
                type: [{ codeHash: { type: String, required: true }, usedAt: { type: Date, default: null } }],
                select: false,
                default: [],
            },

            externalProviders: [
                {
                    provider: { type: String, required: true },
                    providerId: { type: String, required: true },
                    email: { type: String },
                    connectedAt: { type: Date, default: Date.now },
                },
            ],

            profile: {
                firstName: { type: String, trim: true },
                lastName: { type: String, trim: true },
                displayName: { type: String, trim: true },
                avatarUrl: { type: String },
                locale: { type: String, default: 'en' },
                zoneinfo: { type: String },
            },

            // Opaque, consumer-defined data (e.g. business-domain fields the host
            // application wants persisted alongside identity). The package never
            // reads or validates the shape of this field.
            metadata: { type: mongoose.Schema.Types.Mixed, default: {} },
        },
        { timestamps: true }
    );

    schema.index({ status: 1 });
    // findByEmail matches `emailHash` OR `email` (rows from before the blind index): without this index
    // the `email` branch of that $or scans the whole collection on every login.
    schema.index({ email: 1 });
    schema.index({ lockUntil: 1 }, { sparse: true });

    schema.pre('save', function () {
        if (this.email && (this.isModified('email') || !this.emailHash)) {
            this.emailHash = hashEmail(this.email);
        }
    });

    schema.plugin(mongoIdPlugin);

    return connection.model('IdpIdentityUser', schema);
}
