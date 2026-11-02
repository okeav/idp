import crypto from 'crypto';

/**
 * Apple requires a short-lived ES256-signed JWT as the OAuth client_secret,
 * regenerated before every token exchange. This is Apple's own requirement
 * for its client-assertion format — unrelated to (and independent of) this
 * package's own RS256 user-token signing keys.
 */
function generateAppleClientSecret(appleConfig) {
    const { teamId, keyId, clientId, privateKeyPem } = appleConfig;
    if (!teamId || !keyId || !clientId || !privateKeyPem) {
        throw new Error('Apple SSO is not fully configured (teamId, keyId, clientId, privateKeyPem required)');
    }

    const now = Math.floor(Date.now() / 1000);
    const header = Buffer.from(JSON.stringify({ alg: 'ES256', kid: keyId })).toString('base64url');
    // Minted per exchange, so it only needs to outlive one request: 5 minutes, not Apple's 6-month
    // maximum — a secret that leaks from a log is then useless almost immediately.
    const payload = Buffer.from(JSON.stringify({ iss: teamId, iat: now, exp: now + 300, aud: APPLE_ISSUER, sub: clientId })).toString('base64url');
    const signingInput = `${header}.${payload}`;
    const sign = crypto.createSign('SHA256');
    sign.update(signingInput);
    sign.end();
    const signature = sign.sign({ key: privateKeyPem, dsaEncoding: 'ieee-p1363' }).toString('base64url');
    return `${signingInput}.${signature}`;
}

const MULTI_TENANT_AUTHORITIES = new Set(['common', 'organizations', 'consumers']);
const APPLE_ISSUER = 'https://appleid.apple.com';
const DEFAULT_PROVIDER_TIMEOUT_MS = 10_000;

/** Builds the provider table from `config.oauthProviders` + `config.sso.baseCallbackUrl`. Providers with no clientId configured are omitted. */
export function buildSsoProviders(config) {
    const p = config.oauthProviders || {};
    const callbackFor = (provider) => `${config.sso?.baseCallbackUrl?.replace(/\/$/, '') || ''}/sso/${provider}/callback`;

    const providers = {};

    if (p.google?.clientId) {
        providers.google = {
            name: 'google',
            authorizationUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
            tokenUrl: 'https://oauth2.googleapis.com/token',
            userInfoUrl: 'https://www.googleapis.com/oauth2/v3/userinfo',
            clientId: p.google.clientId, clientSecret: p.google.clientSecret,
            scopes: ['openid', 'email', 'profile'],
            redirectUri: callbackFor('google'),
            pkce: true,
        };
    }

    if (p.github?.clientId) {
        providers.github = {
            name: 'github',
            authorizationUrl: 'https://github.com/login/oauth/authorize',
            tokenUrl: 'https://github.com/login/oauth/access_token',
            userInfoUrl: 'https://api.github.com/user',
            userEmailsUrl: 'https://api.github.com/user/emails',
            clientId: p.github.clientId, clientSecret: p.github.clientSecret,
            scopes: ['read:user', 'user:email'],
            redirectUri: callbackFor('github'),
            pkce: true,
        };
    }

    if (p.microsoft?.clientId) {
        // `tenant` defaults to "common" — multitenant work/school + personal
        // Microsoft accounts. This is the one piece of the audited source
        // that was already fully generic (a hardcoded literal, not an
        // Okeav-specific value) — kept as-is, just made configurable.
        const tenant = p.microsoft.tenant || 'common';
        providers.microsoft = {
            name: 'microsoft',
            // Graph's `mail` / `userPrincipalName` are set by whichever tenant's admin owns the account,
            // and Microsoft does not verify them — with a multi-tenant authority, anyone can create a
            // tenant and give a user `mail = victim@yourcompany.com` ("nOAuth"). The address is only
            // trusted when the authority is pinned to one tenant (yours), or explicitly via `trustEmail`.
            emailTrusted: p.microsoft.trustEmail === true || !MULTI_TENANT_AUTHORITIES.has(String(tenant).toLowerCase()),
            authorizationUrl: `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/authorize`,
            tokenUrl: `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`,
            userInfoUrl: 'https://graph.microsoft.com/v1.0/me',
            clientId: p.microsoft.clientId, clientSecret: p.microsoft.clientSecret,
            scopes: ['openid', 'email', 'profile', 'User.Read'],
            redirectUri: callbackFor('microsoft'),
            pkce: true,
        };
    }

    if (p.apple?.clientId) {
        providers.apple = {
            name: 'apple',
            authorizationUrl: 'https://appleid.apple.com/auth/authorize',
            tokenUrl: 'https://appleid.apple.com/auth/token',
            clientId: p.apple.clientId,
            scopes: ['openid', 'email', 'name'],
            redirectUri: callbackFor('apple'),
            responseMode: 'form_post',
            // The identity comes from Apple's id_token, so it is bound to this login with a nonce.
            nonce: true,
            getClientSecret: () => generateAppleClientSecret(p.apple),
        };
    }

    if (p.linkedin?.clientId) {
        providers.linkedin = {
            name: 'linkedin',
            authorizationUrl: 'https://www.linkedin.com/oauth/v2/authorization',
            tokenUrl: 'https://www.linkedin.com/oauth/v2/accessToken',
            userInfoUrl: 'https://api.linkedin.com/v2/userinfo',
            clientId: p.linkedin.clientId, clientSecret: p.linkedin.clientSecret,
            scopes: ['openid', 'profile', 'email'],
            redirectUri: callbackFor('linkedin'),
        };
    }

    return providers;
}

/**
 * Whether SSO may send the browser back to `uri`. Fails closed: without a non-empty
 * `config.sso.allowedRedirectOrigins` nothing is allowed (initIdentityProvider refuses to start with
 * SSO providers but no allowlist) — an open redirect at the end of a real provider login is a
 * convincing phishing step. Only https (or http to localhost) origins on the list pass.
 */
export function isAllowedRedirectUri(config, uri) {
    const allowed = config.sso?.allowedRedirectOrigins;
    if (!Array.isArray(allowed) || allowed.length === 0) return false;
    let url;
    try {
        url = new URL(uri);
    } catch {
        return false;
    }
    const schemeOk = url.protocol === 'https:' || (url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname));
    return schemeOk && !url.username && !url.password && allowed.includes(url.origin);
}

/**
 * Checks Apple's id_token. It arrives over TLS straight from Apple's token endpoint in exchange for
 * our client-authenticated code request, which OIDC Core §3.1.3.7 accepts in place of a signature
 * check — but the claims must still be ours: issuer, audience (our client id), expiry, and the
 * nonce this login sent.
 */
export function assertAppleIdToken(providerConfig, idTokenPayload, expectedNonce) {
    const now = Math.floor(Date.now() / 1000);
    const aud = Array.isArray(idTokenPayload?.aud) ? idTokenPayload.aud : [idTokenPayload?.aud];
    if (idTokenPayload?.iss !== APPLE_ISSUER) throw new Error('Apple id_token: unexpected issuer');
    if (!aud.includes(providerConfig.clientId)) throw new Error('Apple id_token: unexpected audience');
    if (!(typeof idTokenPayload.exp === 'number' && idTokenPayload.exp > now - 60)) throw new Error('Apple id_token: expired');
    if (!expectedNonce || idTokenPayload.nonce !== expectedNonce) throw new Error('Apple id_token: nonce mismatch');
}

export function decodeJwtPayload(token) {
    const [, payload] = String(token).split('.');
    return JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
}

function providerFetch(config, url, init) {
    return fetch(url, { ...init, redirect: 'error', signal: AbortSignal.timeout(config.sso?.providerTimeoutMs ?? DEFAULT_PROVIDER_TIMEOUT_MS) });
}

// Apple sends email_verified as the string "true"; the others as a boolean.
const isTrue = (v) => v === true || v === 'true';

/**
 * Normalizes each provider's raw profile response into a consistent shape. `emailVerified` is true
 * only when the provider itself asserts it verified the address — it decides whether this identity
 * may be linked to (or create) a local account by email. `providerConfig` is needed for Microsoft.
 */
export function normalizeUserInfo(provider, raw, providerConfig = {}) {
    switch (provider) {
        case 'google':
            return { providerId: raw.sub, email: raw.email, emailVerified: isTrue(raw.email_verified), firstName: raw.given_name || null, lastName: raw.family_name || null, name: raw.name, avatarUrl: raw.picture };
        case 'github':
            return {
                // fetchUserInfo replaces `email` with the account's primary *verified* address (or null).
                providerId: String(raw.id), email: raw.email, emailVerified: isTrue(raw.email_verified),
                firstName: raw.name?.split(' ')[0] || null,
                lastName: raw.name?.split(' ').slice(1).join(' ') || null,
                name: raw.name || raw.login, avatarUrl: raw.avatar_url,
            };
        case 'microsoft':
            return { providerId: raw.id, email: raw.mail || raw.userPrincipalName, emailVerified: providerConfig.emailTrusted === true, firstName: raw.givenName || null, lastName: raw.surname || null, name: raw.displayName, avatarUrl: null };
        case 'apple': {
            const payload = decodeJwtPayload(raw.id_token);
            const appleUser = raw.appleUser;
            return {
                providerId: payload.sub, email: payload.email || null, emailVerified: isTrue(payload.email_verified),
                firstName: appleUser?.name?.firstName || null, lastName: appleUser?.name?.lastName || null,
                name: [appleUser?.name?.firstName, appleUser?.name?.lastName].filter(Boolean).join(' ') || payload.sub,
                avatarUrl: null,
            };
        }
        case 'linkedin':
            return { providerId: raw.sub, email: raw.email, emailVerified: isTrue(raw.email_verified), firstName: raw.given_name || null, lastName: raw.family_name || null, name: raw.name || [raw.given_name, raw.family_name].filter(Boolean).join(' '), avatarUrl: raw.picture || null };
        default:
            throw new Error(`Unknown provider: ${provider}`);
    }
}

export async function exchangeCode(config, providerConfig, code, { codeVerifier } = {}) {
    const clientSecret = providerConfig.getClientSecret ? providerConfig.getClientSecret() : providerConfig.clientSecret;
    const params = new URLSearchParams({
        grant_type: 'authorization_code', code, redirect_uri: providerConfig.redirectUri, client_id: providerConfig.clientId, client_secret: clientSecret,
        ...(codeVerifier ? { code_verifier: codeVerifier } : {}),
    });

    const response = await providerFetch(config, providerConfig.tokenUrl, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' }, body: params.toString() });
    if (!response.ok) {
        throw new Error(`SSO provider ${providerConfig.name} returned ${response.status} during code exchange`);
    }
    return response.json();
}

export async function fetchUserInfo(config, providerConfig, accessToken) {
    const response = await providerFetch(config, providerConfig.userInfoUrl, { headers: { Authorization: `Bearer ${accessToken}`, Accept: 'application/json' } });
    if (!response.ok) throw new Error(`SSO provider ${providerConfig.name} returned ${response.status} fetching user info`);
    const info = await response.json();

    // GitHub's profile `email` is whatever public address the user chose to show, and carries no
    // verification status — only the emails endpoint says which address is verified. Always use the
    // primary verified one; without it there is no trustworthy email at all.
    if (providerConfig.name === 'github' && providerConfig.userEmailsUrl) {
        info.email = null;
        info.email_verified = false;
        const emailRes = await providerFetch(config, providerConfig.userEmailsUrl, { headers: { Authorization: `Bearer ${accessToken}`, Accept: 'application/json' } });
        if (emailRes.ok) {
            const emails = await emailRes.json();
            const primary = Array.isArray(emails) ? emails.find((e) => e.primary && e.verified) : null;
            if (primary) {
                info.email = primary.email;
                info.email_verified = true;
            }
        }
    }
    return info;
}
