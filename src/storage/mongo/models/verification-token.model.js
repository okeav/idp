import mongoose from 'mongoose';
import { mongoIdPlugin } from '../plugins/mongo-id.plugin.js';

/**
 * Merges the audited "PasswordResetToken" and "EmailVerificationToken"
 * collections into one — identical shape, identical lifecycle
 * (create → atomic single-use consume → delete-all-for-user), differing
 * only in `kind`.
 */
export function defineVerificationTokenModel(connection) {
    const schema = new mongoose.Schema(
        {
            kind: { type: String, enum: ['password_reset', 'email_verification', 'magic_link'], required: true, index: true },
            user: { type: mongoose.Schema.Types.ObjectId, ref: 'IdpIdentityUser', required: true, index: true },
            tokenHash: { type: String, required: true },
            verificationCode: { type: String }, // email_verification only — short numeric code as an alternative to the link token
            expiresAt: { type: Date, required: true },
            usedAt: { type: Date, default: null },
        },
        { timestamps: true }
    );

    schema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
    schema.index({ kind: 1, tokenHash: 1, user: 1 });
    schema.index({ kind: 1, user: 1 });

    schema.plugin(mongoIdPlugin);

    return connection.model('IdpVerificationToken', schema);
}
