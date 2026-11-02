import { cookiesAreSecure, hostCookieName } from '../utils/cookies.js';

/**
 * The cookie that ties an SSO login to the browser that started it (see initiate.controller.js).
 * One cookie per attempt — named after the state — so two logins in two tabs don't overwrite each
 * other. httpOnly, scoped to the attempt's lifetime. SameSite=Lax is sent on the provider's
 * top-level GET redirect back; Apple returns with a cross-site form POST, which only carries a
 * SameSite=None (hence Secure) cookie.
 */
export function ssoBindingCookie(state, csrfState, providerConfig) {
    const crossSitePost = providerConfig?.responseMode === 'form_post';
    const secure = crossSitePost ? true : cookiesAreSecure(state);
    return {
        // Host-only and `__Host-` (when Secure): it only has to come back to the IdP itself, and a
        // binding cookie planted from a sibling subdomain would bind the victim's browser to the
        // ATTACKER's login attempt — exactly the login CSRF it exists to stop.
        name: hostCookieName(secure, ssoBindingCookieName(csrfState)),
        options: {
            httpOnly: true,
            secure,
            sameSite: crossSitePost ? 'none' : 'lax',
            path: '/',
            maxAge: state.config.ttls.ssoState * 1000,
        },
    };
}

export function ssoBindingCookieName(csrfState) {
    return `idp_sso_${String(csrfState).slice(0, 16)}`;
}
