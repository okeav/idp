import { layout } from '../lib/layout.js';

export function mountRegisterFlow(app, { AUTH_PREFIX }) {
    app.get('/flows/register', (req, res) => {
        res.send(layout({
            title: '1. Register → verify email',
            body: `
      <div class="card">
        <p class="step">Step 1 — register a new account. This calls the real <code>${AUTH_PREFIX}/register</code> endpoint.</p>
        <label>Email</label>
        <input id="email" value="harness-user-${Date.now()}@example.com">
        <label>Password</label>
        <input id="password" value="Str0ng!Passw0rd">
        <label>First name</label>
        <input id="firstName" value="Harness">
        <label>Last name</label>
        <input id="lastName" value="Tester">
        <button onclick="doRegister()">Register</button>
        <pre id="register-result" class="result"></pre>
      </div>

      <div class="card">
        <p class="step">Step 2 — in a real app, <code>onVerificationEmailRequested</code> would send this via your mailer. In dev mode it's captured here instead — this IS the raw hook payload, not a guess.</p>
        <button onclick="fetchDevToken()">Fetch captured verification token/code</button>
        <pre id="dev-token-result" class="result"></pre>
      </div>

      <div class="card">
        <p class="step">Step 3 — verify using either the raw token or the 6-digit code (both are accepted by <code>${AUTH_PREFIX}/register/verify-email</code>).</p>
        <label>Code</label>
        <input id="code">
        <button onclick="doVerify()">Verify email</button>
        <pre id="verify-result" class="result"></pre>
        <p class="step">Once verified, go to <a href="/flows/login">2. Login</a> with the same email/password.</p>
      </div>

      <script>
        async function doRegister() {
          const body = { email: document.getElementById('email').value, password: document.getElementById('password').value,
                          firstName: document.getElementById('firstName').value, lastName: document.getElementById('lastName').value };
          const result = await callApi('${AUTH_PREFIX}/register', { method: 'POST', body });
          showResult('register-result', result);
        }
        async function fetchDevToken() {
          const email = document.getElementById('email').value;
          const res = await fetch('/api/dev-token?email=' + encodeURIComponent(email) + '&kind=verification');
          const entry = await res.json();
          document.getElementById('dev-token-result').textContent = JSON.stringify(entry, null, 2);
          if (entry?.data?.verificationCode) document.getElementById('code').value = entry.data.verificationCode;
        }
        async function doVerify() {
          const email = document.getElementById('email').value;
          const code = document.getElementById('code').value;
          const result = await callApi('${AUTH_PREFIX}/register/verify-email', { method: 'POST', body: { email, code } });
          showResult('verify-result', result);
        }
      </script>`,
        }));
    });
}
