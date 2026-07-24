import crypto from 'crypto';
import { layout } from '../lib/layout.js';
import { rememberPendingAuthorize, lookupPendingAuthorize } from '../lib/oauth-test-store.js';

export function mountOAuth2Flow(app, { AUTH_PREFIX, BASE_URL }) {
    const CALLBACK_URL = `${BASE_URL}/oauth2-callback`;

    app.get('/flows/oauth2', (req, res) => {
        res.send(layout({
            title: '9. OAuth2 / OIDC authorization-code flow',
            body: `
      <div class="flag">Log in first via <a href="/flows/login">2. Login</a> — <code>/oauth2/authorize</code> needs your existing session cookie to know who's granting consent.</div>

      <div class="card">
        <p class="step">Step 1 — self-register a test OAuth client. Lands <code>PENDING_APPROVAL</code> (this package has no admin-role concept of its own — see idp-core's README).</p>
        <button onclick="registerClient()">Register OAuth client</button>
        <pre id="register-result" class="result"></pre>
      </div>

      <div class="card">
        <p class="step">Step 2 — approve it (the approve endpoint is intentionally unauthenticated in this package — mount your own admin-auth in front of it in a real app).</p>
        <button onclick="approveClient()">Approve client</button>
        <pre id="approve-result" class="result"></pre>
      </div>

      <div class="card">
        <p class="step">Step 3 — authorize. Uses <code>fetch()</code> with redirects followed automatically, all in one script — not two separate page loads — so there's no in-between page where consent state can get lost. First click will show <code>consent_required</code> below with a "Grant consent" button; click that, and it'll finish the redirect through to <code>/oauth2-callback</code> itself. Click "Authorize" again afterward (same client) and it skips consent entirely, since it's now on file.</p>
        <button onclick="authorize()">Authorize (requests openid profile email)</button>
        <pre id="authorize-result" class="result"></pre>
        <div id="consent-section" style="display:none">
          <button onclick="grantConsent()">Grant consent (openid profile email)</button>
        </div>
      </div>

      <p class="step">→ Consenting (or an already-consented Authorize) lands you on <a href="/oauth2-callback">/oauth2-callback</a>, which continues with token exchange, userinfo, introspection, and revocation.</p>

      <script>
        let client = null;
        let pendingConsent = null;
        async function registerClient() {
          const body = {
            name: 'Harness Test Client', slug: 'harness-client-' + Date.now(),
            redirectUris: ['${CALLBACK_URL}'], allowedScopes: ['openid','profile','email'], allowedGrants: ['authorization_code','refresh_token'],
          };
          const result = await callApi('${AUTH_PREFIX}/oauth2/clients', { method: 'POST', body });
          showResult('register-result', result);
          if (result.body?.clientId) client = result.body;
        }
        async function approveClient() {
          if (!client) { alert('Register a client first.'); return; }
          const result = await callApi('${AUTH_PREFIX}/oauth2/clients/' + client.clientId + '/approve', { method: 'POST' });
          showResult('approve-result', result);
        }
        async function authorize() {
          if (!client) { alert('Register + approve a client first.'); return; }
          const prep = await fetch('/api/oauth2-test/prepare-authorize', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ clientId: client.clientId, clientSecret: client.clientSecret }),
          });
          const { authorizeUrl } = await prep.json();

          const res = await fetch(authorizeUrl); // same-origin — sends your login cookie automatically
          if (res.redirected) { window.location.href = res.url; return; } // already consented — code is in res.url
          const body = await res.json();
          document.getElementById('authorize-result').textContent = JSON.stringify(body, null, 2);
          document.getElementById('consent-section').style.display = body.action === 'consent_required' ? 'block' : 'none';
          if (body.action === 'consent_required') pendingConsent = body; // has client_id/redirect_uri/scope/state straight from THIS response — nothing stashed across a page load
        }
        async function grantConsent() {
          if (!pendingConsent) { alert('Click "Authorize" first.'); return; }
          const { client_id, redirect_uri, scope, state } = pendingConsent;
          const res = await fetch('${AUTH_PREFIX}/oauth2/authorize/confirm', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ client_id, redirect_uri, scope, state }),
          });
          if (res.redirected) { window.location.href = res.url; return; }
          const body = await res.json().catch(() => null);
          document.getElementById('authorize-result').textContent = 'Unexpected (no redirect): ' + JSON.stringify(body);
        }
      </script>`,
        }));
    });

    app.post('/api/oauth2-test/prepare-authorize', (req, res) => {
        const { clientId, clientSecret } = req.body;
        const state = crypto.randomBytes(16).toString('hex');
        rememberPendingAuthorize(state, { clientId, clientSecret });
        const authorizeUrl = `${AUTH_PREFIX}/oauth2/authorize?` + new URLSearchParams({
            client_id: clientId, redirect_uri: CALLBACK_URL, response_type: 'code', scope: 'openid profile email', state,
        }).toString();
        res.json({ authorizeUrl, state });
    });

    app.get('/oauth2-callback', (req, res) => {
        const { code, state, error, error_description } = req.query;
        const pending = state ? lookupPendingAuthorize(String(state)) : null;

        res.send(layout({
            title: 'OAuth2 callback',
            body: `
      <div class="card">
        <p class="step">Raw query string this endpoint received:</p>
        <pre class="result">${JSON.stringify(req.query, null, 2)}</pre>
      </div>
      ${error ? `<div class="flag blocked">Authorization failed: <strong>${error}</strong> — ${error_description || ''}</div>` : ''}
      ${!code ? '<div class="flag">No <code>code</code> present — go back to <a href="/flows/oauth2">9. OAuth2</a> and grant consent first if you saw consent_required.</div>' : `
      <div class="card">
        <p class="step">Step 4 — exchange the code for tokens.</p>
        <button onclick="exchange()">Exchange code for tokens</button>
        <pre id="exchange-result" class="result"></pre>
      </div>
      <div id="token-display"></div>
      <div id="id-token-display"></div>

      <div class="card">
        <p class="step">Step 5 — call <code>/userinfo</code> with the access token as a Bearer header.</p>
        <button onclick="callUserinfo()">Call /userinfo</button>
        <pre id="userinfo-result" class="result"></pre>
      </div>

      <div class="card">
        <p class="step">Step 6 — introspect (RFC 7662). Note: this package's <code>token</code> field here means the <strong>refresh</strong> token, not the JWT access token — introspection is keyed off the session record. Also note <code>/oauth2/token/introspect</code> requires your own login cookie (flagged as unusual for RFC 7662 in idp-core's README).</p>
        <button onclick="introspect()">Introspect refresh_token</button>
        <pre id="introspect-result" class="result"></pre>
      </div>

      <div class="card">
        <p class="step">Step 7 — revoke (RFC 7009). Always returns 200 per spec, whether or not the token existed.</p>
        <button class="danger" onclick="revoke()">Revoke refresh_token</button>
        <pre id="revoke-result" class="result"></pre>
        <p class="step">Introspect again after revoking — <code>active</code> should now be <code>false</code>.</p>
      </div>

      <script>
        const clientId = ${JSON.stringify(pending?.clientId || null)};
        const clientSecret = ${JSON.stringify(pending?.clientSecret || null)};
        let tokens = null;
        async function exchange() {
          const body = { grant_type: 'authorization_code', code: ${JSON.stringify(code || null)}, redirect_uri: '${CALLBACK_URL}', client_id: clientId, client_secret: clientSecret };
          const result = await callApi('${AUTH_PREFIX}/oauth2/token', { method: 'POST', body });
          showResult('exchange-result', result);
          if (result.body?.access_token) {
            tokens = result.body;
            renderTokenPair('token-display', { accessToken: tokens.access_token, refreshToken: tokens.refresh_token, accessTokenExpiresAt: 'in ' + tokens.expires_in + 's' });
            if (tokens.id_token) {
              const decoded = decodeJwt(tokens.id_token);
              document.getElementById('id-token-display').innerHTML = '<div class="card"><strong>ID token claims</strong><pre class="result">' + JSON.stringify(decoded.payload, null, 2) + '</pre></div>';
            }
          }
        }
        async function callUserinfo() {
          if (!tokens) { alert('Exchange the code first.'); return; }
          // credentials:'omit' is required here, not just tidy: authContextMiddleware
          // prefers the access_token COOKIE over an Authorization: Bearer header when
          // both are present, and you still have a login cookie from authorizing this
          // client in the first place — without this, /userinfo would silently answer
          // using that password-login session's (unscoped) claims instead of this
          // OAuth2 token's actual openid/profile/email scope.
          const result = await callApi('${AUTH_PREFIX}/userinfo', { headers: { Authorization: 'Bearer ' + tokens.access_token }, credentials: 'omit' });
          showResult('userinfo-result', result);
        }
        async function introspect() {
          if (!tokens) { alert('Exchange the code first.'); return; }
          const result = await callApi('${AUTH_PREFIX}/oauth2/token/introspect', { method: 'POST', body: { token: tokens.refresh_token } });
          showResult('introspect-result', result);
        }
        async function revoke() {
          if (!tokens) { alert('Exchange the code first.'); return; }
          const result = await callApi('${AUTH_PREFIX}/oauth2/token/revoke', { method: 'POST', body: { token: tokens.refresh_token, client_id: clientId, client_secret: clientSecret } });
          showResult('revoke-result', result);
        }
      </script>`}`,
        }));
    });
}
