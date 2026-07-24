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
    const payload = Buffer.from(JSON.stringify({ iss: teamId, iat: now, exp: now + 15_777_000, aud: 'https://appleid.apple.com', sub: clientId })).toString('base64url');
    const signingInput = `${header}.${payload}`;
    const sign = crypto.createSign('SHA256');
    sign.update(signingInput);
    sign.end();
    const signature = sign.sign({ key: privateKeyPem, dsaEncoding: 'ieee-p1363' }).toString('base64url');
    return `${signingInput}.${signature}`;
}

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
            authorizationUrl: `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/authorize`,
            tokenUrl: `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`,
            userInfoUrl: 'https://graph.microsoft.com/v1.0/me',
            clientId: p.microsoft.clientId, clientSecret: p.microsoft.clientSecret,
            scopes: ['openid', 'email', 'profile', 'User.Read'],
            redirectUri: callbackFor('microsoft'),
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

export function isAllowedRedirectUri(config, uri) {
    const allowed = config.sso?.allowedRedirectOrigins;
    if (!allowed || allowed.length === 0) return true; // no allowlist configured — consumer opted out of this check
    try {
        return allowed.includes(new URL(uri).origin);
    } catch {
        return false;
    }
}

/** Normalizes each provider's raw profile response into a consistent shape. */
export function normalizeUserInfo(provider, raw) {
    switch (provider) {
        case 'google':
            return { providerId: raw.sub, email: raw.email, firstName: raw.given_name || null, lastName: raw.family_name || null, name: raw.name, avatarUrl: raw.picture };
        case 'github':
            return {
                providerId: String(raw.id), email: raw.email,
                firstName: raw.name?.split(' ')[0] || null,
                lastName: raw.name?.split(' ').slice(1).join(' ') || null,
                name: raw.name || raw.login, avatarUrl: raw.avatar_url,
            };
        case 'microsoft':
            return { providerId: raw.id, email: raw.mail || raw.userPrincipalName, firstName: raw.givenName || null, lastName: raw.surname || null, name: raw.displayName, avatarUrl: null };
        case 'apple': {
            const payload = decodeJwtPayload(raw.id_token);
            const appleUser = raw.appleUser;
            return {
                providerId: payload.sub, email: payload.email || null,
                firstName: appleUser?.name?.firstName || null, lastName: appleUser?.name?.lastName || null,
                name: [appleUser?.name?.firstName, appleUser?.name?.lastName].filter(Boolean).join(' ') || payload.sub,
                avatarUrl: null,
            };
        }
        case 'linkedin':
            return { providerId: raw.sub, email: raw.email, firstName: raw.given_name || null, lastName: raw.family_name || null, name: raw.name || [raw.given_name, raw.family_name].filter(Boolean).join(' '), avatarUrl: raw.picture || null };
        default:
            throw new Error(`Unknown provider: ${provider}`);
    }
}

function decodeJwtPayload(token) {
    const [, payload] = token.split('.');
    return JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
}

export async function exchangeCode(providerConfig, code) {
    const clientSecret = providerConfig.getClientSecret ? providerConfig.getClientSecret() : providerConfig.clientSecret;
    const params = new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: providerConfig.redirectUri, client_id: providerConfig.clientId, client_secret: clientSecret });

    const response = await fetch(providerConfig.tokenUrl, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' }, body: params.toString() });
    if (!response.ok) {
        throw new Error(`SSO provider ${providerConfig.name} returned ${response.status} during code exchange`);
    }
    return response.json();
}

export async function fetchUserInfo(providerConfig, accessToken) {
    const response = await fetch(providerConfig.userInfoUrl, { headers: { Authorization: `Bearer ${accessToken}`, Accept: 'application/json' } });
    if (!response.ok) throw new Error(`SSO provider ${providerConfig.name} returned ${response.status} fetching user info`);
    const info = await response.json();

    if (providerConfig.name === 'github' && !info.email && providerConfig.userEmailsUrl) {
        const emailRes = await fetch(providerConfig.userEmailsUrl, { headers: { Authorization: `Bearer ${accessToken}`, Accept: 'application/json' } });
        if (emailRes.ok) {
            const emails = await emailRes.json();
            const primary = emails.find((e) => e.primary && e.verified);
            if (primary) info.email = primary.email;
        }
    }
    return info;
}
