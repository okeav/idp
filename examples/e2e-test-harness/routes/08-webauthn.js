import { layout } from '../lib/layout.js';

export function mountWebauthnFlow(app, { AUTH_PREFIX }) {
    app.get('/flows/webauthn', (req, res) => {
        res.send(layout({
            title: '8. WebAuthn / passkeys',
            extraScripts: ['/webauthn-client.js'],
            body: `
      <div class="flag">Real browser ceremony — this calls <code>navigator.credentials.create()/.get()</code>, so it needs an actual passkey provider (Windows Hello, Touch ID, a security key, or your OS's password manager offering to save a passkey). Must be opened over <code>http://localhost:...</code> (not a raw IP) — that's the one origin WebAuthn treats as a secure context without HTTPS.</div>

      <h2>8a. Register a passkey (requires login)</h2>
      <div class="flag">Log in first via <a href="/flows/login">2. Login</a> — registering a passkey adds it to your already-authenticated account.</div>
      <div class="card">
        <button onclick="doRegister()">Register a passkey</button>
        <pre id="register-result" class="result"></pre>
      </div>

      <h2>8b. Primary passwordless login</h2>
      <div class="card">
        <p class="step">Log out first (flow 4) so this proves the passkey alone gets you a session — no password involved. Leave email blank for a usernameless/discoverable challenge, or fill it in to scope the challenge to one account.</p>
        <label>Email (optional)</label>
        <input id="login-email">
        <button onclick="doLogin()">Login with passkey</button>
        <pre id="login-result" class="result"></pre>
        <div id="token-display"></div>
      </div>

      <h2>8c. As an MFA second factor</h2>
      <div class="card">
        <p class="step">Enable TOTP MFA first (flow 6), <em>then</em> register a passkey above while still logged in. Afterward, a normal password login will stop at the MFA gate — complete it here with the passkey instead of a TOTP code.</p>
        <label>Email</label><input id="mfa-email">
        <label>Password</label><input id="mfa-password" value="Str0ng!Passw0rd">
        <button onclick="triggerMfa()">Login (trigger MFA gate)</button>
        <pre id="trigger-result" class="result"></pre>
        <label>mfaChallengeToken</label><input id="mfa-challenge-token">
        <button onclick="completeMfa()">Complete MFA with passkey</button>
        <pre id="mfa-result" class="result"></pre>
        <div id="mfa-token-display"></div>
      </div>

      <script>
        async function doRegister() {
          try {
            const result = await webauthnRegister('${AUTH_PREFIX}');
            showResult('register-result', result);
          } catch (err) { document.getElementById('register-result').textContent = 'Browser/ceremony error: ' + err.message; }
        }
        async function doLogin() {
          try {
            const email = document.getElementById('login-email').value || undefined;
            const result = await webauthnLogin('${AUTH_PREFIX}', email);
            showResult('login-result', result);
            if (result.body?.accessToken) renderTokenPair('token-display', result.body);
          } catch (err) { document.getElementById('login-result').textContent = 'Browser/ceremony error: ' + err.message; }
        }
        async function triggerMfa() {
          const body = { email: document.getElementById('mfa-email').value, password: document.getElementById('mfa-password').value };
          const result = await callApi('${AUTH_PREFIX}/login', { method: 'POST', body });
          showResult('trigger-result', result);
          if (result.body?.mfaChallengeToken) document.getElementById('mfa-challenge-token').value = result.body.mfaChallengeToken;
        }
        async function completeMfa() {
          try {
            const token = document.getElementById('mfa-challenge-token').value;
            const result = await webauthnMfa('${AUTH_PREFIX}', token);
            showResult('mfa-result', result);
            if (result.body?.accessToken) renderTokenPair('mfa-token-display', result.body);
          } catch (err) { document.getElementById('mfa-result').textContent = 'Browser/ceremony error: ' + err.message; }
        }
      </script>`,
        }));
    });
}
