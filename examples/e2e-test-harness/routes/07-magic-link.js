import { layout } from '../lib/layout.js';

export function mountMagicLinkFlow(app, { AUTH_PREFIX }) {
    app.get('/flows/magic-link', (req, res) => {
        res.send(layout({
            title: '7. Magic link (passwordless email login)',
            body: `
      <div class="card">
        <p class="step">Try a brand-new email first (new-user signup path), then run it again with the SAME email a second time (existing-user login path — no duplicate account created).</p>
        <label>Email</label>
        <input id="email" value="harness-magic-${Date.now()}@example.com">
        <button onclick="request()">Request magic link</button>
        <pre id="request-result" class="result"></pre>
      </div>

      <div class="card">
        <p class="step">Dev-mode capture of what <code>onMagicLinkRequested</code> would have emailed — includes <code>isNewUser</code> so you can confirm which path it took.</p>
        <button onclick="fetchDevToken()">Fetch captured magic-link token</button>
        <pre id="dev-token-result" class="result"></pre>
      </div>

      <div class="card">
        <p class="step">Verify — this issues a full session through the exact same <code>resolveAuthContext</code> path as password/SSO/WebAuthn login (check the activity panel for <code>MAGIC_LINK_LOGIN</code>).</p>
        <label>Token</label>
        <input id="token">
        <button onclick="verify()">Verify magic link</button>
        <pre id="verify-result" class="result"></pre>
      </div>
      <div id="token-display"></div>

      <script>
        async function request() {
          const email = document.getElementById('email').value;
          const result = await callApi('${AUTH_PREFIX}/magic-link/request', { method: 'POST', body: { email } });
          showResult('request-result', result);
        }
        async function fetchDevToken() {
          const email = document.getElementById('email').value;
          const res = await fetch('/api/dev-token?email=' + encodeURIComponent(email) + '&kind=magic-link');
          const entry = await res.json();
          document.getElementById('dev-token-result').textContent = JSON.stringify(entry, null, 2);
          if (entry?.data?.magicLinkToken) document.getElementById('token').value = entry.data.magicLinkToken;
        }
        async function verify() {
          const token = document.getElementById('token').value;
          const result = await callApi('${AUTH_PREFIX}/magic-link/verify', { method: 'POST', body: { token } });
          showResult('verify-result', result);
          if (result.body?.accessToken) renderTokenPair('token-display', result.body);
        }
      </script>`,
        }));
    });
}
