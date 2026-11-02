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
        <p class="step">Step 1 — register a test OAuth client (confidential, so it has a secret). Lands <code>PENDING_APPROVAL</code>. The <code>/oauth2/clients*</code> routes only exist because <code>server.js</code> passes <code>buildRouter({ clientManagement: { middleware } })</code> — this package has no admin-role concept of its own, so the harness's middleware accepts any logged-in user (a <code>401</code> here means you're not logged in). Redirect URIs must be <code>https</code>, or <code>http</code> only to <code>localhost</code>/<code>127.0.0.1</code>/<code>[::1]</code> — this harness's <code>${CALLBACK_URL}</code> qualifies.</p>
        <button onclick="registerClient()">Register OAuth client</button>
        <pre id="register-result" class="result"></pre>
      </div>

      <div class="card">
        <p class="step">Step 2 — approve it (behind the same <code>clientManagement</code> middleware — a real app's own admin check goes there).</p>
        <button onclick="approveClient()">Approve client</button>
        <pre id="approve-result" class="result"></pre>
      </div>

      <div class="card">
        <p class="step">Step 3 — authorize. The harness's relying-party side generates a fresh PKCE pair (<code>code_challenge</code> + <code>code_challenge_method=S256</code> — required for every client by default) and an OIDC <code>nonce</code> for each attempt. Uses <code>fetch()</code> with redirects followed automatically, all in one script, so there's no in-between page where consent state can get lost. The first click shows <code>consent_required</code> with a single-use <code>consent_challenge</code>; "Grant consent" posts <em>only</em> that challenge (the server stored the validated request) and follows the redirect through to <code>/oauth2-callback</code>. Click "Authorize" again afterward (same client) and it skips consent, since it's now on file.</p>
        <button onclick="authorize()">Authorize (requests openid profile email)</button>
        <pre id="authorize-result" class="result"></pre>
        <div id="consent-section" style="display:none">
          <button onclick="answerConsent('confirm')">Grant consent</button>
          <button class="danger" onclick="answerConsent('deny')">Deny (expect error=access_denied on the callback)</button>
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
          document.getElementById('authorize-result').textContent = 'HTTP ' + res.status + '\\n\\n' + JSON.stringify(body, null, 2);
          document.getElementById('consent-section').style.display = body.action === 'consent_required' ? 'block' : 'none';
          pendingConsent = body.action === 'consent_required' ? body : null; // the consent_challenge comes straight from THIS response
        }
        async function answerConsent(kind) {
          if (!pendingConsent) { alert('Click "Authorize" first.'); return; }
          const res = await fetch('${AUTH_PREFIX}/oauth2/authorize/' + kind, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ consent_challenge: pendingConsent.consent_challenge }),
          });
          pendingConsent = null; // single-use either way
          if (res.redirected) { window.location.href = res.url; return; }
          const body = await res.json().catch(() => null);
          document.getElementById('authorize-result').textContent = 'Unexpected (no redirect): HTTP ' + res.status + '\\n\\n' + JSON.stringify(body, null, 2);
        }
      </script>`,
        }));
    });

    // The relying party's half of the authorization request: a fresh state,
    // PKCE verifier/challenge (S256) and OIDC nonce per attempt, remembered
    // server-side by `state` so the callback can finish the exchange.
    app.post('/api/oauth2-test/prepare-authorize', (req, res) => {
        const { clientId, clientSecret } = req.body;
        const state = crypto.randomBytes(16).toString('hex');
        const codeVerifier = crypto.randomBytes(32).toString('base64url'); // 43 chars
        const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
        const nonce = crypto.randomBytes(16).toString('base64url');
        rememberPendingAuthorize(state, { clientId, clientSecret, codeVerifier, nonce });
        const authorizeUrl = `${AUTH_PREFIX}/oauth2/authorize?` + new URLSearchParams({
            client_id: clientId, redirect_uri: CALLBACK_URL, response_type: 'code', scope: 'openid profile email', state,
            code_challenge: codeChallenge, code_challenge_method: 'S256', nonce,
        }).toString();
        res.json({ authorizeUrl, state });
    });

    app.get('/oauth2-callback', (req, res) => {
        const { code, state, error, error_description, iss } = req.query;
        const pending = state ? lookupPendingAuthorize(String(state)) : null;
        const issOk = iss === BASE_URL;

        res.send(layout({
            title: 'OAuth2 callback',
            body: `
      <div class="card">
        <p class="step">Raw query string this endpoint received:</p>
        <pre class="result">${escapeHtml(JSON.stringify(req.query, null, 2))}</pre>
        <p class="step">RFC 9207 <code>iss</code> check (a real client refuses the response unless it names the authorization server it sent the user to): <span class="badge ${issOk ? 'ok' : 'bad'}">${issOk ? 'iss matches ' + escapeHtml(BASE_URL) : 'iss missing or wrong'}</span></p>
      </div>
      ${error ? `<div class="flag blocked">Authorization failed: <strong>${escapeHtml(error)}</strong> — ${escapeHtml(error_description || '')}</div>` : ''}
      ${!code ? '<div class="flag">No <code>code</code> present — go back to <a href="/flows/oauth2">9. OAuth2</a> and grant consent first if you saw consent_required.</div>' : `
      <div class="card">
        <p class="step">Step 4 — exchange the code for tokens. Sends the PKCE <code>code_verifier</code> generated for this attempt. Choose how the client authenticates — both are implemented: <code>client_secret_post</code> (id + secret in the body) or <code>client_secret_basic</code> (HTTP Basic header).</p>
        <label>Client authentication</label>
        <select id="auth-method"><option value="post">client_secret_post</option><option value="basic">client_secret_basic</option></select>
        <button onclick="exchange()">Exchange code for tokens</button>
        <pre id="exchange-result" class="result"></pre>
      </div>
      <div id="token-display"></div>
      <div id="id-token-display"></div>

      <div class="card">
        <p class="step">Step 5 — call <code>/userinfo</code> with the access token as a Bearer header. It only accepts an OAuth2 <em>user</em> access token carrying the <code>openid</code> scope, and releases <code>email</code>/profile claims only for the granted scopes. (Your password-login token would be refused here — and conversely this token is refused on the IdP's own first-party routes like <code>/me</code>; try the second button.)</p>
        <button onclick="callUserinfo()">Call /userinfo</button>
        <button class="secondary" onclick="callMe()">Call /me with this OAuth2 token (expect 401)</button>
        <pre id="userinfo-result" class="result"></pre>
      </div>

      <div class="card">
        <p class="step">Step 6 — introspect (RFC 7662). Requires the calling client to authenticate (and be confidential); it only describes tokens issued to that client. Works on both the refresh token and the JWT access token.</p>
        <button onclick="introspect('refresh_token')">Introspect refresh_token</button>
        <button class="secondary" onclick="introspect('access_token')">Introspect access_token</button>
        <pre id="introspect-result" class="result"></pre>
      </div>

      <div class="card">
        <p class="step">Step 7 — revoke (RFC 7009). Requires client authentication; always returns 200 per spec, whether or not the token existed (another client's token is silently ignored).</p>
        <button class="danger" onclick="revoke()">Revoke refresh_token</button>
        <pre id="revoke-result" class="result"></pre>
        <p class="step">Introspect again after revoking — <code>active</code> should now be <code>false</code>.</p>
      </div>

      <script>
        const clientId = ${jsLiteral(pending?.clientId || null)};
        const clientSecret = ${jsLiteral(pending?.clientSecret || null)};
        const codeVerifier = ${jsLiteral(pending?.codeVerifier || null)};
        const expectedNonce = ${jsLiteral(pending?.nonce || null)};
        let tokens = null;
        // Client credentials, per the method chosen above (post = in the body, basic = Authorization header).
        function clientAuth(body) {
          if (document.getElementById('auth-method').value === 'basic') {
            const basic = btoa(encodeURIComponent(clientId) + ':' + encodeURIComponent(clientSecret));
            return { body, headers: { Authorization: 'Basic ' + basic } };
          }
          return { body: { ...body, client_id: clientId, client_secret: clientSecret }, headers: {} };
        }
        async function exchange() {
          const auth = clientAuth({ grant_type: 'authorization_code', code: ${jsLiteral(code || null)}, redirect_uri: '${CALLBACK_URL}', code_verifier: codeVerifier });
          const result = await callApi('${AUTH_PREFIX}/oauth2/token', { method: 'POST', body: auth.body, headers: auth.headers, credentials: 'omit' });
          showResult('exchange-result', result);
          if (result.body?.access_token) {
            tokens = result.body;
            renderTokenPair('token-display', { accessToken: tokens.access_token, refreshToken: tokens.refresh_token, accessTokenExpiresAt: 'in ' + tokens.expires_in + 's' });
            if (tokens.id_token) {
              const decoded = decodeJwt(tokens.id_token);
              const nonceOk = decoded.payload?.nonce === expectedNonce;
              document.getElementById('id-token-display').innerHTML = '<div class="card"><strong>ID token claims</strong> ' +
                '<span class="badge ' + (nonceOk ? 'ok' : 'bad') + '">' + (nonceOk ? 'nonce matches this attempt' : 'nonce MISMATCH') + '</span>' +
                '<pre class="result">' + escapeHtml(JSON.stringify(decoded.payload, null, 2)) + '</pre></div>';
            }
          }
        }
        // credentials:'omit' is required here, not just tidy: authContextMiddleware
        // prefers the access_token COOKIE over an Authorization: Bearer header when
        // both are present, and you still have a (first-party) login cookie from
        // authorizing this client — which /userinfo now refuses outright.
        async function callUserinfo() {
          if (!tokens) { alert('Exchange the code first.'); return; }
          const result = await callApi('${AUTH_PREFIX}/userinfo', { headers: { Authorization: 'Bearer ' + tokens.access_token }, credentials: 'omit' });
          showResult('userinfo-result', result);
        }
        async function callMe() {
          if (!tokens) { alert('Exchange the code first.'); return; }
          const result = await callApi('${AUTH_PREFIX}/me', { headers: { Authorization: 'Bearer ' + tokens.access_token }, credentials: 'omit' });
          showResult('userinfo-result', result);
        }
        async function introspect(which) {
          if (!tokens) { alert('Exchange the code first.'); return; }
          const auth = clientAuth({ token: tokens[which], token_type_hint: which });
          const result = await callApi('${AUTH_PREFIX}/oauth2/token/introspect', { method: 'POST', body: auth.body, headers: auth.headers, credentials: 'omit' });
          showResult('introspect-result', result);
        }
        async function revoke() {
          if (!tokens) { alert('Exchange the code first.'); return; }
          const auth = clientAuth({ token: tokens.refresh_token, token_type_hint: 'refresh_token' });
          const result = await callApi('${AUTH_PREFIX}/oauth2/token/revoke', { method: 'POST', body: auth.body, headers: auth.headers, credentials: 'omit' });
          showResult('revoke-result', result);
        }
      </script>`}`,
        }));
    });
}

// The callback echoes attacker-influenced query values into the page.
function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

// A value embedded in an inline <script> — JSON, with `<` escaped so a query value can't close the tag.
function jsLiteral(v) {
    return JSON.stringify(v).replace(/</g, '\u003c');
}
