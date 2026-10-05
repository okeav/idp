import express from 'express';
import cookieParserLib from 'cookie-parser';
import { buildRouter } from '../../src/routes/build-router.js';
import { setState } from '../../src/config/state.js';

/**
 * Serves `buildRouter(routerOpts)` on its own ephemeral port. With `state`,
 * every request first makes that state the active singleton — which is how
 * one test process stands up two "instances" (two `initIdentityProvider`
 * states, each with its own per-process cache, sharing one database). Only
 * sound while requests run one at a time, as these tests do.
 *
 * @param {{ routerOpts?: object, state?: object, trustProxy?: boolean }} [opts]
 */
export async function serve({ routerOpts = {}, state = null, trustProxy = false } = {}) {
    const app = express();
    if (trustProxy) app.set('trust proxy', true);
    if (state) {
        app.use((_req, _res, next) => {
            setState(state);
            next();
        });
    }
    app.use(cookieParserLib());
    app.use(express.json());
    app.use('/', buildRouter(routerOpts));
    app.use((err, _req, res, _next) => {
        res.status(err.httpStatus || 500).json({ error: err.code || 'INTERNAL_ERROR', message: err.message });
    });

    const server = await new Promise((resolve) => {
        const s = app.listen(0, () => resolve(s));
    });
    return {
        baseUrl: `http://127.0.0.1:${server.address().port}`,
        stop: () => new Promise((resolve) => server.close(resolve)),
    };
}

export const json = (body, extraHeaders = {}) => ({
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...extraHeaders },
    body: JSON.stringify(body),
});
