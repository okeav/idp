import { layout } from '../lib/layout.js';

export function mountRegisterFlow(app, { AUTH_PREFIX }) {
    app.get('/flows/register', (req, res) => {
        res.send(layout({
            title: '1. Register → verify email',
            body: `
      <div class="card">
        <p class="step">Step 1 — register a new account. This calls the real <code>${AUTH_PREFIX}/register</code> endpoint, which always answers <code>{ status: 'ok', verificationTicket }</code> and sets the <code>__Host-verification_ticket</code> cookie (a ticket for the address, issued the same way whether or not it has an account, so the answer reveals nothing; registering again from this browser keeps the same ticket).</p>
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
        <p class="step">Step 3 — verify using either the raw token or the 6-digit code (both are accepted by <code>${AUTH_PREFIX}/register/verify-email</code>). This page's request carries the ticket cookie, so its wrong codes spend this browser's own budget (5) — someone guessing at the address without the ticket spends the per-address budget and can't lock this browser out. A client without cookies would send <code>ticket</code> in the body instead. From the 4th verification email for an address within the code's lifetime no code is issued (<code>verificationCode: null</code> in step 2) — step 2 then fills in the token, and the link path is used.</p>
        <label>Code (or token)</label>
        <input id="code">
        <p class="step">Only needed if this address was registered <em>more than once</em> before verification (click Register twice to try it): the endpoint then answers <code>400 REGISTRATION_PASSWORD_REQUIRED</code> until you also send the password of the registration the code came from — the code stays usable, so just fill this in and verify again (a <em>wrong</em> password answers <code>400 INVALID_OR_EXPIRED_TOKEN</code>, like a wrong code). Leave it empty otherwise.</p>
        <label>Password (contested registrations only)</label>
        <input id="verifyPassword" placeholder="leave empty unless asked">
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
          // No code once the address has had 3 in the code's lifetime: fall back to the link token.
          const value = entry?.data?.verificationCode || entry?.data?.verificationToken;
          if (value) document.getElementById('code').value = value;
        }
        async function doVerify() {
          const email = document.getElementById('email').value;
          const value = document.getElementById('code').value.trim();
          const password = document.getElementById('verifyPassword').value;
          // Six digits: the code (budgeted); anything else: the link token (no budget).
          const body = /^[0-9]{6}$/.test(value) ? { email, code: value } : { email, token: value };
          if (password) body.password = password;
          const result = await callApi('${AUTH_PREFIX}/register/verify-email', { method: 'POST', body });
          showResult('verify-result', result);
        }
      </script>`,
        }));
    });
}
