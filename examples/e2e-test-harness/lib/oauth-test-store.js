// Maps the OAuth2 `state` CSRF value back to which harness-registered test
// client initiated the flow, so the callback page can pre-fill the token
// exchange form. A real OAuth client app keeps exactly this kind of
// server-side bookkeeping (it's just usually a session store, not a plain
// Map) — this isn't an idp-core concept, it's ordinary relying-party state.
const pending = new Map();

export function rememberPendingAuthorize(state, data) {
    pending.set(state, data);
}

// Deliberately non-destructive (a peek, not a pop). The harness's
// authorize()/grantConsent() client JS calls fetch() with redirects
// followed automatically, then re-navigates the browser to the same final
// URL via window.location.href — which means the server actually processes
// GET /oauth2-callback TWICE for one click: once invisibly inside fetch's
// redirect-following, once for the visible navigation. A single-use "pop"
// here would empty this out on the first (invisible) hit, leaving
// client_id/client_secret null by the time the page you actually see loads
// — exactly the bug that caused a null client_id to fail token-exchange
// validation. Unbounded growth across a manual test session is a complete
// non-issue for a throwaway, single-process harness.
export function lookupPendingAuthorize(state) {
    return pending.get(state) || null;
}
