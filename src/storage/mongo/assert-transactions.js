import { IdpError } from '../../errors/idp-error.js';

// MongoDB has used this exact wording since transactions were introduced in
// 4.0 and it hasn't changed since — safe to match on it directly rather than
// a driver-specific error code, which varies more across server/driver
// version combinations.
const UNSUPPORTED_MESSAGE_FRAGMENT = 'Transaction numbers are only allowed on a replica set member or mongos';

/**
 * Three of this package's flows (login, MFA-verify, SSO callback) write
 * through a real multi-document Mongo transaction
 * (`SessionRepository.createSessionForLogin`). Transactions require the
 * target deployment to be a replica set (including a single-node one) or a
 * sharded cluster — a plain standalone `mongod` cannot run them at all.
 *
 * Rather than let that surface as a confusing failure on someone's first
 * login attempt, this runs a real (but read-only, no-op) transaction once at
 * startup and fails loudly and immediately if the deployment can't support
 * it.
 *
 * @param {import('mongoose').Connection} connection
 * @param {import('mongoose').Model} anyModel - any already-registered model on `connection`; used to run a harmless `findOne` inside the probe transaction.
 */
export async function assertTransactionsSupported(connection, anyModel) {
    const session = await connection.startSession();
    try {
        await session.withTransaction(async () => {
            await anyModel.findOne({}).session(session);
        });
    } catch (err) {
        if (isUnsupportedTransactionsError(err)) {
            throw new IdpError({
                code: 'MONGO_TRANSACTIONS_UNSUPPORTED',
                httpStatus: 500,
                message:
                    'This MongoDB deployment does not support transactions, which @okeav/idp-core requires ' +
                    '(login, MFA verification, and SSO callback each write through a multi-document transaction). ' +
                    'MongoDB transactions require a replica set (a single-node one is enough) or a sharded cluster — ' +
                    'a plain standalone mongod cannot run them.\n\n' +
                    'Fastest fix for local dev: use the docker-compose.yml shipped in this package\'s repo root ' +
                    '(docker compose up) — it starts a single-node replica set with rs.initiate() already run for you.\n\n' +
                    'If you already have a standalone mongod running (dev or otherwise) and don\'t want to switch to ' +
                    'the compose file, converting it in place is a one-command change, not a reinstall: stop mongod, ' +
                    'restart it with `--replSet rs0` added to its command line (or `replication.replSetName: rs0` in ' +
                    'mongod.conf), then connect a mongo shell once and run `rs.initiate()`. Existing data is preserved.',
                cause: err,
            });
        }
        throw err;
    } finally {
        await session.endSession();
    }
}

function isUnsupportedTransactionsError(err) {
    if (!err) return false;
    if (typeof err.message === 'string' && err.message.includes(UNSUPPORTED_MESSAGE_FRAGMENT)) return true;
    // Fallback: MongoDB reports this as IllegalOperation (code 20) in every
    // server version transactions have existed in.
    if (err.code === 20 || err.codeName === 'IllegalOperation') return true;
    return false;
}
