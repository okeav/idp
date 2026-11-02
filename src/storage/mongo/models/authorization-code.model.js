import mongoose from 'mongoose';
import { mongoIdPlugin } from '../plugins/mongo-id.plugin.js';

export function defineAuthorizationCodeModel(connection) {
    const schema = new mongoose.Schema(
        {
            code: { type: String, required: true, unique: true, index: true },
            clientId: { type: String, required: true, index: true },
            userId: { type: mongoose.Schema.Types.ObjectId, ref: 'IdpIdentityUser', required: true, index: true },
            redirectUri: { type: String, required: true },
            scopes: [{ type: String }],
            codeChallenge: { type: String },
            codeChallengeMethod: { type: String, enum: ['S256', 'plain', null] },
            // OIDC: the nonce from the authorization request, echoed into the ID token.
            nonce: { type: String, default: null },
            // When the user last logged in at the IdP — the ID token's auth_time.
            authTime: { type: Date, default: null },
            expiresAt: { type: Date, required: true, index: { expireAfterSeconds: 0 } },
            used: { type: Boolean, default: false },
            usedAt: { type: Date, default: null },
            // The access-token session (jti) that authorized the code: if it is revoked before redemption, so is the code.
            sessionJti: { type: String, default: null },
            // The user's sessionEpoch and the consent's version when the code was issued: a "sign out
            // everywhere" or a consent change before redemption refuses it.
            sessionEpoch: { type: Number, default: 0 },
            consentVersion: { type: Number, default: null },
            // Set when the code is presented again after redemption — everything it produced is then revoked.
            reuseDetectedAt: { type: Date, default: null },
        },
        { timestamps: true }
    );

    schema.index({ code: 1, used: 1 });
    schema.index({ clientId: 1, used: 1, expiresAt: 1 });
    schema.plugin(mongoIdPlugin);

    return connection.model('IdpAuthorizationCode', schema);
}
