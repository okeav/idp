import { layout } from '../lib/layout.js';

export function mountSsoFlow(app, { BASE_URL, IDP_BASE_URL, googleConfigured }) {
    const redirectUri = `${BASE_URL}/sso-callback`;
    const googleCallbackUrl = `${IDP_BASE_URL}/sso/google/callback`;

    app.get('/flows/sso', (req, res) => {
        res.send(layout({
            title: '10. SSO (social login)',
            body: googleConfigured
                ? `
      <div class="card">
        <p class="step">Google SSO is configured. This is a real, unmodified <code>initiateSsoHandler</code> → Google consent screen → <code>ssoCallbackHandler</code> round trip — nothing here is stubbed.</p>
        <a href="${IDP_BASE_URL}/sso/google?redirect_uri=${encodeURIComponent(redirectUri)}">Login with Google</a>
      </div>`
                : `
      <div class="flag blocked">
        <strong>Not configured — needs your input.</strong> This package's SSO providers (Google/GitHub/Microsoft/Apple/LinkedIn) use hardcoded real provider endpoints (see idp-core <code>src/sso/providers.js</code>) — there is no way to stub or fake this round trip without either real credentials or modifying idp-core itself, which this harness intentionally does not do. Real SSO fundamentally requires a live third-party identity provider.
        <br><br>
        <strong>To unblock this flow, supply:</strong>
        <ol>
          <li>A Google Cloud OAuth 2.0 Client ID (Web application type) — console.cloud.google.com → APIs &amp; Services → Credentials.</li>
          <li>Authorized redirect URI on that client, set to exactly: <code>${googleCallbackUrl}</code></li>
          <li>Set <code>GOOGLE_CLIENT_ID</code> and <code>GOOGLE_CLIENT_SECRET</code> in this harness's <code>.env</code> file (see <code>.env.example</code>).</li>
          <li>Restart <code>npm start</code>.</li>
        </ol>
        Everything else in this harness works without any credentials from you — this is the one flow that structurally can't.
      </div>`,
        }));
    });

    app.get('/sso-callback', async (req, res) => {
        const { ssoLogin, error, error_description } = req.query;
        let meResult = null;
        let refreshedTokens = null;
        try {
            const meRes = await fetch(`${IDP_BASE_URL}/me`, { headers: { cookie: req.headers.cookie || '' } });
            meResult = { status: meRes.status, body: await meRes.json() };
        } catch { /* not logged in — fine, shown below */ }

        res.send(layout({
            title: 'SSO callback',
            body: `
      <div class="card">
        <p class="step">Raw query string this endpoint received:</p>
        <pre class="result">${JSON.stringify(req.query, null, 2)}</pre>
      </div>
      ${error ? `<div class="flag blocked">SSO failed: <strong>${error}</strong> — ${error_description || ''}</div>` : ''}
      ${ssoLogin === 'success' ? `
      <div class="card">
        <p class="step"><code>/auth/me</code> right now (proves the session cookie from SSO login actually works):</p>
        <pre class="result">${JSON.stringify(meResult, null, 2)}</pre>
      </div>
      <div class="card">
        <p class="step">Call <code>/auth/refresh</code> to see (and decode) the actual JWT this SSO login produced — the callback itself only sets cookies, it doesn't return a JSON token body, so this is how to reveal it.</p>
        <button onclick="reveal()">Reveal token via refresh</button>
        <div id="token-display"></div>
      </div>
      <script>
        async function reveal() {
          const result = await callApi('${IDP_BASE_URL}/refresh', { method: 'POST', body: {} });
          if (result.body?.accessToken) renderTokenPair('token-display', result.body);
          else document.getElementById('token-display').innerHTML = '<pre class="result err">' + JSON.stringify(result.body, null, 2) + '</pre>';
        }
      </script>` : ''}`,
        }));
    });
}
