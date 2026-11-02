/**
 * The cookie that ties an SSO login to the browser that started it (see initiate.controller.js).
 * One cookie per attempt — named after the state — so two logins in two tabs don't overwrite each
 * other. httpOnly, scoped to the attempt's lifetime. SameSite=Lax is sent on the provider's
 * top-level GET redirect back; Apple returns with a cross-site form POST, which only carries a
 * SameSite=None (hence Secure) cookie.
 */
export function ssoBindingCookie(state, csrfState, providerConfig) {
    const secure = state.config.cookies?.secure ?? process.env.NODE_ENV !== 'development';
    const crossSitePost = providerConfig?.responseMode === 'form_post';
    return {
        name: ssoBindingCookieName(csrfState),
        options: {
            httpOnly: true,
            secure: crossSitePost ? true : secure,
            sameSite: crossSitePost ? 'none' : 'lax',
            path: '/',
            maxAge: state.config.ttls.ssoState * 1000,
            ...(state.config.cookies?.domain ? { domain: state.config.cookies.domain } : {}),
        },
    };
}

export function ssoBindingCookieName(csrfState) {
    return `idp_sso_${String(csrfState).slice(0, 16)}`;
}
