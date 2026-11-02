import { layout } from '../lib/layout.js';

export function mountMfaFlow(app, { AUTH_PREFIX }) {
    app.get('/flows/mfa', (req, res) => {
        res.send(layout({
            title: '6. MFA (TOTP)',
            body: `
      <div class="flag">Requires an active login cookie (from <a href="/flows/login">2. Login</a>) for setup/confirm/disable — those are self-service "me" endpoints. <strong>Setup and confirm are step-up protected:</strong> they need a real login within the last 15 minutes (<code>session.recentAuthMaxAgeSeconds</code>) — a refreshed token doesn't count. If you get <code>401 REAUTHENTICATION_REQUIRED</code>, log in again and retry.</div>
      <div class="flag"><strong>Each TOTP code works once.</strong> After a code is accepted (confirm, a login challenge, regenerating recovery codes, disable) the same code — and anything earlier — is refused with <code>INVALID_MFA_CODE</code>. Wait for the next 30-second step before the next step that needs a code; the "compute" buttons show how long the current step has left.</div>

      <div class="card">
        <p class="step">Step 1 — initiate setup. Returns the raw <code>otpauth://</code> URI (this package ships no QR renderer — paste the URI into any otpauth-compatible tool, or use the convenience "compute code" buttons, which run the exact same TOTP algorithm your authenticator app would; the secret is kept in this browser's localStorage so other flows' pages can compute codes too).</p>
        <button onclick="setup()">Setup MFA</button>
        <pre id="setup-result" class="result"></pre>
      </div>

      <div class="card">
        <p class="step">Step 2 — confirm with a 6-digit code. Manual field — paste a code from a real authenticator, or click "compute" as a convenience since this is a headless test harness. Confirming revokes the account's <em>other</em> sessions (any other login of this account stops working); the session you're enrolling from survives.</p>
        <label>Code</label>
        <input id="confirm-code">
        <button class="secondary" onclick="computeTotpInto('confirm-code')">Compute current code (convenience only)</button>
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
        <p class="step">Step 4 — complete the challenge with a TOTP code — a <em>new</em> one, not the code you confirmed with — or an unused recovery code from step 2's response (<code>XXXXX-XXXXX-XXXXX-XXXXX</code>; any case, spaces and dashes optional). A challenge token completes one login only. The same form also completes a challenge from <a href="/flows/magic-link">7. Magic link</a> or <a href="/flows/sso">10. SSO</a> for an MFA account.</p>
        <label>mfaChallengeToken</label><input id="challenge-token">
        <label>Code</label><input id="challenge-code">
        <button class="secondary" onclick="computeTotpInto('challenge-code')">Compute current code (convenience only)</button>
        <button onclick="verifyChallenge()">Verify MFA challenge</button>
        <pre id="verify-result" class="result"></pre>
      </div>
      <div id="token-display"></div>

      <div class="card">
        <p class="step">Step 5 (optional) — regenerate recovery codes. Needs a current TOTP <code>code</code> as well as the password (the password only if the account has one — a magic-link/SSO-only account sends just the code).</p>
        <label>Password</label><input id="regen-password" value="Str0ng!Passw0rd">
        <label>Code</label><input id="regen-code">
        <button class="secondary" onclick="computeTotpInto('regen-code')">Compute current code (convenience only)</button>
        <button onclick="regenerate()">Regenerate recovery codes</button>
        <pre id="regen-result" class="result"></pre>
      </div>

      <div class="card">
        <p class="step">Step 6 (optional) — disable MFA (a valid current code, plus the password if the account has one — clear the password field for a passwordless account).</p>
        <label>Password</label><input id="disable-password" value="Str0ng!Passw0rd">
        <label>Code</label><input id="disable-code">
        <button class="secondary" onclick="computeTotpInto('disable-code')">Compute current code (convenience only)</button>
        <button class="danger" onclick="disable()">Disable MFA</button>
        <pre id="disable-result" class="result"></pre>
      </div>

      <script>
        // Pre-fill a challenge token handed over from another page (#challenge=... — a fragment never reaches a server log).
        const handedOver = new URLSearchParams(location.hash.slice(1)).get('challenge');
        if (handedOver) document.getElementById('challenge-token').value = handedOver;

        function passwordOrNothing(id) {
          const v = document.getElementById(id).value;
          return v ? { password: v } : {};
        }
        async function setup() {
          const result = await callApi('${AUTH_PREFIX}/me/mfa/setup', { method: 'POST' });
          showResult('setup-result', result);
          if (result.body?.secret) rememberTotpSecret(result.body.secret);
        }
        async function confirm() {
          const code = document.getElementById('confirm-code').value;
          const result = await callApi('${AUTH_PREFIX}/me/mfa/confirm', { method: 'POST', body: { code } });
          showResult('confirm-result', result);
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
        async function regenerate() {
          const body = { ...passwordOrNothing('regen-password'), code: document.getElementById('regen-code').value };
          const result = await callApi('${AUTH_PREFIX}/me/mfa/recovery-codes', { method: 'POST', body });
          showResult('regen-result', result);
        }
        async function disable() {
          const body = { ...passwordOrNothing('disable-password'), code: document.getElementById('disable-code').value };
          const result = await callApi('${AUTH_PREFIX}/me/mfa', { method: 'DELETE', body });
          showResult('disable-result', result);
        }
      </script>`,
        }));
    });
}
