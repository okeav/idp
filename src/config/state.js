// Module-level singleton holding everything `initIdentityProvider()` wires up
// (storage, cache, signing keys, hooks, logger, resolved config). Every
// handler/middleware reads it via `getState()` at call time — this is what
// makes flat named exports (`import { loginHandler } from '...'`) work
// without threading config through every import.
let state = null;

export function setState(s) {
    state = s;
}

export function getState() {
    if (!state) {
        throw new Error('initIdentityProvider(config) must be called once before using any @okeav/idp-core export');
    }
    return state;
}

/** Test/teardown helper — not part of the public surface. */
export function resetState() {
    state = null;
}
