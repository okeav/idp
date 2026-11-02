import { layout } from '../lib/layout.js';

export function mountMagicLinkFlow(app, { AUTH_PREFIX }) {
    app.get('/flows/magic-link', (req, res) => {
        res.send(layout({
            title: '7. Magic link (passwordless email login)',
            body: `
      <div class="card">
        <p class="step">Try a brand-new email first (new-user signup path), then run it again with the SAME email a second time (existing-user login path — no duplicate account created). Requesting a link invalidates every earlier link for that account — only the most recently captured token works. Requests are also limited per address (<code>rateLimiting.magicLinkByEmail</code>, 3 per hour) as well as per IP, so use a fresh email if you hit <code>429</code>.</p>
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
        <p class="step">Verify — this issues a full session through the exact same <code>resolveAuthContext</code> path as password/SSO/WebAuthn login (check the activity panel for <code>MAGIC_LINK_LOGIN</code>). For an account with MFA enabled (e.g. the flow-6 account) it stops at the second factor instead, exactly like password login: <code>{ mfaRequired, mfaChallengeToken, expiresIn }</code> and no session.</p>
        <label>Token</label>
        <input id="token">
        <button onclick="verify()">Verify magic link</button>
        <pre id="verify-result" class="result"></pre>
        <div id="mfa-notice" class="flag" style="display:none">
          This account has MFA enabled — <code>mfaRequired: true</code> was returned instead of a session.
          <a id="mfa-link" href="/flows/mfa">Complete the challenge in 6. MFA (step 4)</a> — the token is pre-filled there.
        </div>
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
          const challenge = result.body?.mfaRequired ? result.body.mfaChallengeToken : null;
          document.getElementById('mfa-notice').style.display = challenge ? 'block' : 'none';
          if (challenge) document.getElementById('mfa-link').href = '/flows/mfa#challenge=' + encodeURIComponent(challenge);
          if (result.body?.accessToken) renderTokenPair('token-display', result.body);
        }
      </script>`,
        }));
    });
}
