import mongoose from 'mongoose';

/**
 * One fixed-window failure counter per key (e.g. `mfa:<userId>`), with an
 * optional lock. Shared by every app instance pointed at this database, which
 * is what makes the per-account MFA lockout hold across a scaled deployment.
 */
export function defineAttemptCounterModel(connection) {
    const schema = new mongoose.Schema(
        {
            key: { type: String, required: true },
            count: { type: Number, required: true, default: 0 },
            windowExpiresAt: { type: Date, required: true },
            lockedUntil: { type: Date, default: null },
            // max(windowExpiresAt, lockedUntil) — when the whole record stops mattering.
            expiresAt: { type: Date, required: true },
        },
        { timestamps: false, versionKey: false }
    );

    schema.index({ key: 1 }, { unique: true });
    schema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

    return connection.model('IdpAttemptCounter', schema);
}
