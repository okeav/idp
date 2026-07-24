import mongoose from 'mongoose';
import { mongoIdPlugin } from '../plugins/mongo-id.plugin.js';
import { CLIENT_TYPES, GRANT_TYPES, OAUTH_CLIENT_STATUS } from '../../../config/constants.js';

/**
 * An OAuth2 "client" / relying party — a third-party app registered to use
 * this IDP for authorization-code-flow login. Renamed from the audited
 * "Tenant" model: that name implied SaaS multi-tenancy of the IDP itself,
 * when it's really just an OAuth2 client registration.
 */
export function defineOAuthClientModel(connection) {
    const schema = new mongoose.Schema(
        {
            name: { type: String, required: true, trim: true },
            slug: { type: String, required: true, unique: true, lowercase: true, trim: true },
            clientId: { type: String, required: true, unique: true, index: true },
            clientSecretHash: { type: String, required: true, select: false },
            clientType: { type: String, enum: Object.values(CLIENT_TYPES), default: CLIENT_TYPES.CONFIDENTIAL },

            redirectUris: [{ type: String, required: true }],
            postLogoutRedirectUris: [{ type: String }],
            allowedScopes: [{ type: String }],
            allowedGrants: [{ type: String, enum: Object.values(GRANT_TYPES), default: GRANT_TYPES.AUTHORIZATION_CODE }],

            accessTokenTTL: { type: Number, default: 3600 },
            refreshTokenTTL: { type: Number, default: 2592000 },
            idTokenTTL: { type: Number, default: 3600 },

            logoUrl: { type: String },
            websiteUrl: { type: String },
            privacyPolicyUrl: { type: String },
            termsOfServiceUrl: { type: String },
            supportEmail: { type: String },

            status: { type: String, enum: Object.values(OAUTH_CLIENT_STATUS), default: OAUTH_CLIENT_STATUS.PENDING_APPROVAL },

            metadata: { type: mongoose.Schema.Types.Mixed, default: {} },
        },
        { timestamps: true }
    );

    schema.plugin(mongoIdPlugin);

    return connection.model('IdpOAuthClient', schema);
}
