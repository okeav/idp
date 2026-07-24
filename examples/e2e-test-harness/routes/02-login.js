import { layout } from '../lib/layout.js';

export function mountLoginFlow(app, { AUTH_PREFIX }) {
    app.get('/flows/login', (req, res) => {
        res.send(layout({
            title: '2. Login (password)',
            body: `
      <div class="card">
        <p class="step">Uses whatever account you registered+verified in flow 1 (or any active account). Sets <code>access_token</code>/<code>refresh_token</code> httpOnly cookies AND returns both in the response body (shown below) — the body values are what get decoded here since JS can't read httpOnly cookies.</p>
        <label>Email</label>
        <input id="email" value="">
        <label>Password</label>
        <input id="password" value="Str0ng!Passw0rd">
        <button onclick="doLogin()">Login</button>
        <pre id="raw-result" class="result"></pre>
      </div>
      <div id="token-display"></div>
      <div id="mfa-notice" class="flag" style="display:none">
        This account has MFA enabled — <code>mfaRequired: true</code> was returned instead of a session.
        Go to <a href="/flows/mfa">6. MFA</a> and use the <code>mfaChallengeToken</code> above to complete login.
      </div>

      <script>
        async function doLogin() {
          const body = { email: document.getElementById('email').value, password: document.getElementById('password').value };
          const result = await callApi('${AUTH_PREFIX}/login', { method: 'POST', body });
          showResult('raw-result', result);
          document.getElementById('mfa-notice').style.display = result.body?.mfaRequired ? 'block' : 'none';
          if (result.body?.accessToken) renderTokenPair('token-display', result.body);
        }
      </script>`,
        }));
    });
}
