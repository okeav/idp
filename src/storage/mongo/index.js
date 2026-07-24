import { connectMongo } from './connection.js';
import { assertTransactionsSupported } from './assert-transactions.js';
import { defineIdentityUserModel } from './models/identity-user.model.js';
import { defineSessionModel, defineAccessTokenAuditModel } from './models/session.model.js';
import { defineAuthorizationCodeModel } from './models/authorization-code.model.js';
import { defineConsentModel } from './models/consent.model.js';
import { defineOAuthClientModel } from './models/oauth-client.model.js';
import { defineVerificationTokenModel } from './models/verification-token.model.js';
import { defineServiceKeyModel } from './models/service-key.model.js';
import { defineCredentialModel } from './models/credential.model.js';

import { MongoUserRepository } from './repositories/mongo-user.repository.js';
import { MongoSessionRepository } from './repositories/mongo-session.repository.js';
import { MongoAuthorizationCodeRepository } from './repositories/mongo-authorization-code.repository.js';
import { MongoConsentRepository } from './repositories/mongo-consent.repository.js';
import { MongoOAuthClientRepository } from './repositories/mongo-oauth-client.repository.js';
import { MongoVerificationTokenRepository } from './repositories/mongo-verification-token.repository.js';
import { MongoServiceKeyRepository } from './repositories/mongo-service-key.repository.js';
import { MongoCredentialRepository } from './repositories/mongo-credential.repository.js';

/**
 * @param {{ uri?: string, connection?: import('mongoose').Connection }} mongoConfig
 * @param {{ hashEmail: (email: string) => string, normalizeEmail: (email: string) => string }} emailDeps
 * @returns {Promise<{
 *   connection: import('mongoose').Connection,
 *   close: () => Promise<void>,
 *   userRepository: import('../interfaces.js').UserRepository,
 *   sessionRepository: import('../interfaces.js').SessionRepository,
 *   authorizationCodeRepository: import('../interfaces.js').AuthorizationCodeRepository,
 *   consentRepository: import('../interfaces.js').ConsentRepository,
 *   oauthClientRepository: import('../interfaces.js').OAuthClientRepository,
 *   verificationTokenRepository: import('../interfaces.js').VerificationTokenRepository,
 *   serviceKeyRepository: import('../interfaces.js').ServiceKeyRepository,
 *   credentialRepository: import('../interfaces.js').CredentialRepository,
 * }>}
 */
export async function createMongoStorage(mongoConfig, emailDeps) {
    const connection = await connectMongo(mongoConfig);

    const userModel = defineIdentityUserModel(connection, emailDeps);
    const sessionModel = defineSessionModel(connection);
    const accessTokenAuditModel = defineAccessTokenAuditModel(connection);
    const authorizationCodeModel = defineAuthorizationCodeModel(connection);
    const consentModel = defineConsentModel(connection);
    const oauthClientModel = defineOAuthClientModel(connection);
    const verificationTokenModel = defineVerificationTokenModel(connection);
    const serviceKeyModel = defineServiceKeyModel(connection);
    const credentialModel = defineCredentialModel(connection);

    // Fail fast, at startup, if this deployment can't run transactions —
    // see assert-transactions.js for why and what this package tells the
    // caller to do about it. Escape hatch for environments that have
    // already verified this out-of-band (e.g. a CI job reusing a known-good
    // Atlas cluster) and want to shave the extra round trip off startup.
    if (!mongoConfig?.skipTransactionCheck) {
        await assertTransactionsSupported(connection, userModel);
    }

    const sessionRepository = new MongoSessionRepository(sessionModel, accessTokenAuditModel, connection);
    // The composite transactional method needs the user model to update
    // lastLoginAt inside the same transaction — injected here rather than
    // baked into the repository's constructor dependency list, since it's
    // only needed for that one method.
    const rawCreateSessionForLogin = sessionRepository.createSessionForLogin.bind(sessionRepository);
    sessionRepository.createSessionForLogin = (input) => rawCreateSessionForLogin({ ...input, userModel });

    return {
        connection,
        close: () => connection.close(),
        userRepository: new MongoUserRepository(userModel, emailDeps),
        sessionRepository,
        authorizationCodeRepository: new MongoAuthorizationCodeRepository(authorizationCodeModel),
        consentRepository: new MongoConsentRepository(consentModel),
        oauthClientRepository: new MongoOAuthClientRepository(oauthClientModel),
        verificationTokenRepository: new MongoVerificationTokenRepository(verificationTokenModel),
        serviceKeyRepository: new MongoServiceKeyRepository(serviceKeyModel),
        credentialRepository: new MongoCredentialRepository(credentialModel),
    };
}
