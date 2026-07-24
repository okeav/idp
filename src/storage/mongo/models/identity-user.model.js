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
            failedLoginAttempts: { type: Number, default: 0 },
            lockUntil: { type: Date, default: null },

            mfaEnabled: { type: Boolean, default: false },
            mfaSecret: { type: String, select: false },
            mfaTempSecret: { type: String, select: false },
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
    schema.index({ lockUntil: 1 }, { sparse: true });

    schema.pre('save', function () {
        if (this.email && (this.isModified('email') || !this.emailHash)) {
            this.emailHash = hashEmail(this.email);
        }
    });

    schema.plugin(mongoIdPlugin);

    return connection.model('IdpIdentityUser', schema);
}
