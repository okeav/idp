import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { generate as generateTotp } from 'otplib';
import { buildTestApp, withTemporaryApp, uniqueEmail, freshTotp } from './helpers/build-test-app.js';
import { json } from './helpers/serve.js';
import { buildSsoProviders, normalizeUserInfo } from '../src/sso/providers.js';

// Issue: the SSO callback linked a provider identity to whichever local account
// had the same email, without asking whether the provider had verified that
// email — so anyone who could put an arbitrary address on a provider account
// (a Microsoft tenant admin setting `mail`, an unverified Google/Apple/LinkedIn
// address, a GitHub public-profile email) logged in as the address's owner.
// SSO also issued a full session to accounts with MFA enabled.
//
// The provider endpoints are stubbed at the fetch layer: every call this
// process makes to a provider host is answered from `profiles` below; every
// other request (the test's own calls to the IdP) goes to the network as usual.

const password = 'Str0ng!Passw0rd';
const redirectUri = 'https://app.example.com/cb?from=login';
const realFetch = globalThis.fetch;
const profiles = {};

function stubProviders() {
    globalThis.fetch = async (input, init) => {
        const url = String(input?.url ?? input);
        if (url === 'https://oauth2.googleapis.com/token' || url === 'https://github.com/login/oauth/access_token' || url.startsWith('https://login.microsoftonline.com/')) {
            return Response.json({ access_token: 'provider-access-token', token_type: 'Bearer' });
        }
        if (url === 'https://www.googleapis.com/oauth2/v3/userinfo') return Response.json(profiles.google);
        if (url === 'https://api.github.com/user') return Response.json(profiles.github);
        if (url === 'https://api.github.com/user/emails') return Response.json(profiles.githubEmails ?? []);
        if (url === 'https://graph.microsoft.com/v1.0/me') return Response.json(profiles.microsoft);
        return realFetch(input, init);
    };
}

const providersConfig = (microsoftTenant = 'common') => ({
    oauthProviders: {
        google: { clientId: 'g-client', clientSecret: 'g-secret' },
        github: { clientId: 'gh-client', clientSecret: 'gh-secret' },
        microsoft: { clientId: 'ms-client', clientSecret: 'ms-secret', tenant: microsoftTenant },
    },
    sso: { baseCallbackUrl: 'https://idp.test.local', allowedRedirectOrigins: ['https://app.example.com'] },
});

let app;

before(async () => {
    stubProviders();
    app = await buildTestApp({ config: providersConfig() });
});

after(async () => {
    globalThis.fetch = realFetch;
    await app.stop();
});

/** Runs initiate → provider → callback with `profile` as the provider's answer. */
async function sso(provider, profile, { baseUrl = app.baseUrl } = {}) {
    Object.assign(profiles, profile);
    const init = await realFetch(`${baseUrl}/sso/${provider}?redirect_uri=${encodeURIComponent(redirectUri)}`, { redirect: 'manual' });
    assert.equal(init.status, 302, await init.text());
    const state = new URL(init.headers.get('location')).searchParams.get('state');
    // The browser carries the binding cookie set at initiate back to the callback.
    const cookie = init.headers.getSetCookie().map((c) => c.split(';')[0]).join('; ');
    const cb = await realFetch(`${baseUrl}/sso/${provider}/callback?code=provider-code&state=${state}`, { redirect: 'manual', headers: { Cookie: cookie } });
    assert.equal(cb.status, 302, await cb.text());
    const location = new URL(cb.headers.get('location'));
    const cookies = cb.headers.getSetCookie().filter((c) => !c.startsWith('__Host-idp_sso_'));
    return { location, cookies, query: location.searchParams, fragment: new URLSearchParams(location.hash.slice(1)) };
}

const post = (path, body, headers) => fetch(`${app.baseUrl}${path}`, json(body, headers));

async function registerVerified(email) {
    await post('/register', { email, password });
    const code = app.hookCalls.onVerificationEmailRequested.filter((c) => c.email === email).at(-1).verificationCode;
    assert.equal((await post('/register/verify-email', { email, code })).status, 200);
    return app.state.storage.userRepository.findByEmail(email);
}

const google = (email, { verified = true, sub = `g-${Math.random()}` } = {}) => ({ google: { sub, email, email_verified: verified, given_name: 'Vic' } });
const linkedTo = (provider, providerId) => app.state.storage.userRepository.findByExternalProvider(provider, providerId);

test('an unverified provider email is never linked to the existing account that owns it', async () => {
    const email = uniqueEmail('unverified-link');
    await registerVerified(email);

    const r = await sso('google', google(email, { verified: false, sub: 'g-attacker-1' }));
    assert.equal(r.query.get('error'), 'email_not_verified');
    assert.equal(r.query.get('from'), 'login', 'an existing query string on redirect_uri is preserved');
    assert.equal(r.cookies.length, 0, 'no session cookies');
    assert.equal(await linkedTo('google', 'g-attacker-1'), null, 'the attacker identity was not linked');
});

test('an unverified provider email does not create an account either (no squatting)', async () => {
    const email = uniqueEmail('unverified-new');
    const r = await sso('google', google(email, { verified: false }));
    assert.equal(r.query.get('error'), 'email_not_verified');
    assert.equal(await app.state.storage.userRepository.findByEmail(email), null);
});

test('a verified provider email links to the active account and logs in', async () => {
    const email = uniqueEmail('verified-link');
    const user = await registerVerified(email);

    const r = await sso('google', google(email, { sub: 'g-owner-1' }));
    assert.equal(r.query.get('ssoLogin'), 'success');
    assert.ok(r.cookies.some((c) => c.startsWith('__Host-access_token=')));
    assert.equal(String((await linkedTo('google', 'g-owner-1')).id), String(user.id));

    // Once linked, the identity keeps working by its provider id.
    const again = await sso('google', google(email, { sub: 'g-owner-1', verified: false }));
    assert.equal(again.query.get('ssoLogin'), 'success', 'an already-linked identity logs in by provider id');
});

test('Microsoft with a multi-tenant authority: `mail` is not trusted, so nothing is linked (nOAuth)', async () => {
    const email = uniqueEmail('noauth-victim');
    await registerVerified(email);

    const r = await sso('microsoft', { microsoft: { id: 'ms-attacker-oid', mail: email, displayName: 'Attacker' } });
    assert.equal(r.query.get('error'), 'email_not_verified');
    assert.equal(await linkedTo('microsoft', 'ms-attacker-oid'), null);
});

test('Microsoft pinned to one tenant: the tenant\'s addresses are trusted', async () => {
    await withTemporaryApp({ config: providersConfig('contoso.onmicrosoft.com') }, async (temp) => {
        const email = uniqueEmail('ms-single-tenant');
        const r = await sso('microsoft', { microsoft: { id: 'ms-oid-1', mail: email, displayName: 'Employee' } }, { baseUrl: temp.baseUrl });
        assert.equal(r.query.get('ssoLogin'), 'success');
    });
});

test('GitHub: the public profile email is ignored; only the primary verified address is used', async () => {
    const victim = uniqueEmail('gh-victim');
    await registerVerified(victim);

    const spoof = await sso('github', { github: { id: 4242, login: 'attacker', email: victim }, githubEmails: [{ email: victim, primary: true, verified: false }] });
    assert.equal(spoof.query.get('error'), 'email_required', 'no verified primary address -> no email at all');
    assert.equal(await linkedTo('github', '4242'), null);

    const own = uniqueEmail('gh-own');
    const ok = await sso('github', { github: { id: 4343, login: 'dev', email: victim }, githubEmails: [{ email: own, primary: true, verified: true }] });
    assert.equal(ok.query.get('ssoLogin'), 'success');
    const user = await linkedTo('github', '4343');
    assert.equal(user.email, own.toLowerCase(), 'the verified primary address is the one used, not the profile email');
});

test('a pending (unverified) account is claimed by the verified owner, and the pre-registered password dies', async () => {
    const email = uniqueEmail('sso-claim');
    await post('/register', { email, password: 'Att4cker!Passw0rd' }); // the attacker's pre-registration

    const r = await sso('google', google(email, { sub: 'g-claimer' }));
    assert.equal(r.query.get('ssoLogin'), 'success');

    const user = await app.state.storage.userRepository.findByEmail(email);
    assert.equal(user.status, 'ACTIVE');
    assert.equal((await post('/login', { email, password: 'Att4cker!Passw0rd' })).status, 401, 'the pre-registered password is gone');
    assert.ok(app.hookCalls.onAuditLog.some((e) => e.action === 'SSO_PENDING_ACCOUNT_CLAIMED' && e.userId === String(user.id)));
});

test('a suspended account gets no new login method attached', async () => {
    const email = uniqueEmail('sso-suspended');
    const user = await registerVerified(email);
    await app.state.storage.userRepository.updateById(user.id, { status: 'SUSPENDED' });

    const r = await sso('google', google(email, { sub: 'g-suspended' }));
    assert.equal(r.query.get('error'), 'account_inactive');
    assert.equal(await linkedTo('google', 'g-suspended'), null);
});

test('SSO stops at the MFA challenge for an account with MFA (no cookies, token in the fragment)', async () => {
    const email = uniqueEmail('sso-mfa');
    const mfaUser = await registerVerified(email);
    const login = await (await post('/login', { email, password })).json();
    const auth = { Authorization: `Bearer ${login.accessToken}` };
    const { secret } = await (await fetch(`${app.baseUrl}/me/mfa/setup`, { method: 'POST', headers: auth })).json();
    assert.equal((await post('/me/mfa/confirm', { code: await generateTotp({ secret }) }, auth)).status, 200);

    const r = await sso('google', google(email, { sub: 'g-mfa' }));
    assert.equal(r.cookies.length, 0, 'no session before the second factor');
    assert.equal(r.query.get('ssoLogin'), null);
    assert.equal(r.query.get('mfa_challenge_token'), null, 'the challenge never travels in the query string');
    assert.equal(r.fragment.get('mfa_required'), '1');
    const mfaChallengeToken = r.fragment.get('mfa_challenge_token');
    assert.ok(mfaChallengeToken);

    const verify = await post('/mfa/verify', { mfaChallengeToken, code: await freshTotp(app.state, mfaUser.id, secret) });
    assert.equal(verify.status, 200);
    assert.ok((await verify.json()).accessToken);
});

test('normalizeUserInfo: email_verified per provider (Apple sends a string)', () => {
    const appleToken = (claims) => `h.${Buffer.from(JSON.stringify(claims)).toString('base64url')}.s`;
    assert.equal(normalizeUserInfo('apple', { id_token: appleToken({ sub: 'a', email: 'x@y.z', email_verified: 'true' }) }).emailVerified, true);
    assert.equal(normalizeUserInfo('apple', { id_token: appleToken({ sub: 'a', email: 'x@y.z', email_verified: 'false' }) }).emailVerified, false);
    assert.equal(normalizeUserInfo('apple', { id_token: appleToken({ sub: 'a', email: 'x@y.z' }) }).emailVerified, false);
    assert.equal(normalizeUserInfo('linkedin', { sub: 'l', email: 'x@y.z', email_verified: true }).emailVerified, true);
    assert.equal(normalizeUserInfo('google', { sub: 'g', email: 'x@y.z' }).emailVerified, false);
});

test('buildSsoProviders: Microsoft email trust follows the authority (or an explicit trustEmail)', () => {
    const ms = (microsoft) => buildSsoProviders({ oauthProviders: { microsoft: { clientId: 'c', ...microsoft } } }).microsoft.emailTrusted;
    assert.equal(ms({}), false, 'default authority is "common"');
    assert.equal(ms({ tenant: 'common' }), false);
    assert.equal(ms({ tenant: 'Organizations' }), false);
    assert.equal(ms({ tenant: 'consumers' }), false);
    assert.equal(ms({ tenant: '72f988bf-86f1-41af-91ab-2d7cd011db47' }), true);
    assert.equal(ms({ tenant: 'common', trustEmail: true }), true);
});
