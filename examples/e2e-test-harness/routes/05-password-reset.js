import { layout } from '../lib/layout.js';

export function mountPasswordResetFlow(app, { AUTH_PREFIX }) {
    app.get('/flows/password-reset', (req, res) => {
        res.send(layout({
            title: '5. Forgot / reset password',
            body: `
      <div class="card">
        <p class="step">Step 1 — request a reset. Enumeration-safe: always returns <code>{status:'ok'}</code> whether or not the email exists.</p>
        <label>Email (must be an existing, verified account — e.g. from flow 1)</label>
        <input id="email">
        <button onclick="requestReset()">Request password reset</button>
        <pre id="request-result" class="result"></pre>
      </div>

      <div class="card">
        <p class="step">Step 2 — dev-mode capture of what <code>onPasswordResetRequested</code> would have emailed you.</p>
        <button onclick="fetchDevToken()">Fetch captured reset token</button>
        <pre id="dev-token-result" class="result"></pre>
      </div>

      <div class="card">
        <p class="step">Step 3 — reset the password. This also revokes every existing session for the account.</p>
        <label>Token</label>
        <input id="token">
        <label>New password</label>
        <input id="newPassword" value="EvenStr0nger!Passw0rd">
        <button onclick="doReset()">Reset password</button>
        <pre id="reset-result" class="result"></pre>
        <p class="step">Then go to <a href="/flows/login">2. Login</a> and confirm the OLD password fails but the new one works.</p>
      </div>

      <script>
        async function requestReset() {
          const email = document.getElementById('email').value;
          const result = await callApi('${AUTH_PREFIX}/password/forgot', { method: 'POST', body: { email } });
          showResult('request-result', result);
        }
        async function fetchDevToken() {
          const email = document.getElementById('email').value;
          const res = await fetch('/api/dev-token?email=' + encodeURIComponent(email) + '&kind=password-reset');
          const entry = await res.json();
          document.getElementById('dev-token-result').textContent = JSON.stringify(entry, null, 2);
          if (entry?.data?.resetToken) document.getElementById('token').value = entry.data.resetToken;
        }
        async function doReset() {
          const email = document.getElementById('email').value;
          const token = document.getElementById('token').value;
          const newPassword = document.getElementById('newPassword').value;
          const result = await callApi('${AUTH_PREFIX}/password/reset', { method: 'POST', body: { email, token, newPassword } });
          showResult('reset-result', result);
        }
      </script>`,
        }));
    });
}
