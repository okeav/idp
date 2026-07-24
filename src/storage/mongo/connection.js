import mongoose from 'mongoose';

/**
 * @param {{ uri?: string, connection?: import('mongoose').Connection }} mongoConfig
 * @returns {Promise<import('mongoose').Connection>} a dedicated connection this
 *   package's models are registered against — never mutates `mongoose.connection`
 *   (the default global connection) so it can coexist with a consumer app that
 *   also uses Mongoose for its own models.
 */
export async function connectMongo(mongoConfig = {}) {
    if (mongoConfig.connection) return mongoConfig.connection;
    if (!mongoConfig.uri) throw new Error('config.mongo.uri (or config.mongo.connection) is required');

    const connection = mongoose.createConnection(mongoConfig.uri);
    await connection.asPromise();
    return connection;
}
