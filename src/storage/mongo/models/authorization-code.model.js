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
        },
        { timestamps: true }
    );

    schema.index({ code: 1, used: 1 });
    schema.index({ clientId: 1, used: 1, expiresAt: 1 });
    schema.plugin(mongoIdPlugin);

    return connection.model('IdpAuthorizationCode', schema);
}
