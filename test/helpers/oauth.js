import crypto from 'crypto';
import assert from 'node:assert/strict';

/** A PKCE (S256) verifier/challenge pair. */
export function pkcePair() {
    const verifier = crypto.randomBytes(32).toString('base64url');
    return { verifier, challenge: crypto.createHash('sha256').update(verifier).digest('base64url') };
}

/**
 * Runs GET /oauth2/authorize as the logged-in user (PKCE S256), confirming consent through the
 * returned consent_challenge when needed. Resolves with the code, the PKCE verifier, and the
 * redirect URL the client would receive.
 */
export async function authorizeCode({ baseUrl, accessToken, clientId, redirectUri, scope = 'openid', state, nonce, pkce = pkcePair() }) {
    const auth = { Authorization: `Bearer ${accessToken}` };
    const qs = new URLSearchParams({
        client_id: clientId, redirect_uri: redirectUri, response_type: 'code', scope,
        code_challenge: pkce.challenge, code_challenge_method: 'S256',
        ...(state ? { state } : {}), ...(nonce ? { nonce } : {}),
    });
    const res = await fetch(`${baseUrl}/oauth2/authorize?${qs}`, { headers: auth, redirect: 'manual' });
    let location;
    if (res.status === 200) {
        const body = await res.json();
        assert.equal(body.action, 'consent_required', JSON.stringify(body));
        const confirm = await fetch(`${baseUrl}/oauth2/authorize/confirm`, {
            method: 'POST', headers: { 'Content-Type': 'application/json', ...auth },
            body: JSON.stringify({ consent_challenge: body.consent_challenge }), redirect: 'manual',
        });
        assert.equal(confirm.status, 302, await confirm.text());
        location = confirm.headers.get('location');
    } else {
        assert.equal(res.status, 302, await res.text());
        location = res.headers.get('location');
    }
    const url = new URL(location);
    return { code: url.searchParams.get('code'), verifier: pkce.verifier, url };
}

/** Exchanges an authorization code at /oauth2/token (client_secret_post). Resolves with { status, body }. */
export async function exchangeCode({ baseUrl, client, code, redirectUri, verifier }) {
    const res = await fetch(`${baseUrl}/oauth2/token`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            grant_type: 'authorization_code', code, redirect_uri: redirectUri, client_id: client.clientId,
            ...(client.clientSecret ? { client_secret: client.clientSecret } : {}), ...(verifier ? { code_verifier: verifier } : {}),
        }),
    });
    return { status: res.status, body: await res.json() };
}
