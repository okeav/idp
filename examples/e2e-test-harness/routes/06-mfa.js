import { layout } from '../lib/layout.js';

export function mountMfaFlow(app, { AUTH_PREFIX }) {
    app.get('/flows/mfa', (req, res) => {
        res.send(layout({
            title: '6. MFA (TOTP)',
            body: `
      <div class="flag">Requires an active login cookie (from <a href="/flows/login">2. Login</a>) for setup/confirm/disable — those are self-service "me" endpoints.</div>

      <div class="card">
        <p class="step">Step 1 — initiate setup. Returns the raw <code>otpauth://</code> URI (this package ships no QR renderer — paste the URI into any otpauth-compatible tool, or use the convenience "compute code" button below, which runs the exact same TOTP algorithm your authenticator app would).</p>
        <button onclick="setup()">Setup MFA</button>
        <pre id="setup-result" class="result"></pre>
      </div>

      <div class="card">
        <p class="step">Step 2 — confirm with a 6-digit code. Manual field — paste a code from a real authenticator, or click "compute" as a convenience since this is a headless test harness.</p>
        <label>Code</label>
        <input id="confirm-code">
        <button class="secondary" onclick="computeCode('confirm-code')">Compute current code from the secret above (convenience only)</button>
        <button onclick="confirm()">Confirm — enable MFA</button>
        <pre id="confirm-result" class="result"></pre>
      </div>

      <div class="card">
        <p class="step">Step 3 — log in again with email+password. Because MFA is now enabled, you'll get <code>mfaRequired:true</code> + a <code>mfaChallengeToken</code> instead of a session.</p>
        <label>Email</label><input id="mfa-email">
        <label>Password</label><input id="mfa-password" value="Str0ng!Passw0rd">
        <button onclick="loginTriggeringMfa()">Login</button>
        <pre id="login-result" class="result"></pre>
      </div>

      <div class="card">
        <p class="step">Step 4 — complete the challenge with a TOTP code (or an unused recovery code from step 2's response).</p>
        <label>mfaChallengeToken</label><input id="challenge-token">
        <label>Code</label><input id="challenge-code">
        <button class="secondary" onclick="computeCode('challenge-code')">Compute current code (convenience only)</button>
        <button onclick="verifyChallenge()">Verify MFA challenge</button>
        <pre id="verify-result" class="result"></pre>
      </div>
      <div id="token-display"></div>

      <div class="card">
        <p class="step">Step 5 (optional) — disable MFA (needs your password + a valid current code).</p>
        <label>Password</label><input id="disable-password" value="Str0ng!Passw0rd">
        <label>Code</label><input id="disable-code">
        <button class="secondary" onclick="computeCode('disable-code')">Compute current code (convenience only)</button>
        <button class="danger" onclick="disable()">Disable MFA</button>
        <pre id="disable-result" class="result"></pre>
      </div>

      <script>
        let lastSecret = null;
        async function setup() {
          const result = await callApi('${AUTH_PREFIX}/me/mfa/setup', { method: 'POST' });
          showResult('setup-result', result);
          if (result.body?.secret) lastSecret = result.body.secret;
        }
        async function confirm() {
          const code = document.getElementById('confirm-code').value;
          const result = await callApi('${AUTH_PREFIX}/me/mfa/confirm', { method: 'POST', body: { code } });
          showResult('confirm-result', result);
        }
        async function computeCode(fieldId) {
          if (!lastSecret) { alert('Run "Setup MFA" first — the secret is only known after that.'); return; }
          const res = await fetch('/api/totp/compute', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ secret: lastSecret }) });
          const { code } = await res.json();
          document.getElementById(fieldId).value = code;
        }
        async function loginTriggeringMfa() {
          const body = { email: document.getElementById('mfa-email').value, password: document.getElementById('mfa-password').value };
          const result = await callApi('${AUTH_PREFIX}/login', { method: 'POST', body });
          showResult('login-result', result);
          if (result.body?.mfaChallengeToken) document.getElementById('challenge-token').value = result.body.mfaChallengeToken;
        }
        async function verifyChallenge() {
          const body = { mfaChallengeToken: document.getElementById('challenge-token').value, code: document.getElementById('challenge-code').value };
          const result = await callApi('${AUTH_PREFIX}/mfa/verify', { method: 'POST', body });
          showResult('verify-result', result);
          if (result.body?.accessToken) renderTokenPair('token-display', result.body);
        }
        async function disable() {
          const body = { password: document.getElementById('disable-password').value, code: document.getElementById('disable-code').value };
          const result = await callApi('${AUTH_PREFIX}/me/mfa', { method: 'DELETE', body });
          showResult('disable-result', result);
        }
      </script>`,
        }));
    });
}
