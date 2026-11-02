import { layout } from '../lib/layout.js';

export function mountRefreshFlow(app, { AUTH_PREFIX }) {
    app.get('/flows/refresh', (req, res) => {
        res.send(layout({
            title: '3. Refresh token rotation',
            body: `
      <div class="card">
        <p class="step">Paste the <code>refreshToken</code> value from <a href="/flows/login">2. Login</a> (or any active session) below.
        Every successful refresh <strong>rotates</strong> the refresh token — the old value is revoked immediately, even though it hasn't expired.</p>
        <p class="step"><strong>Reuse detection (0.4.0):</strong> replaying an already-rotated token within ~10 s (<code>session.refreshReuseGraceSeconds</code> — two tabs refreshing at once) is just refused. Replay it <em>after</em> that and it's treated as theft: the whole family (this login) is revoked — the current token in the box stops working too — and <code>REFRESH_TOKEN_REUSE_DETECTED</code> appears in the activity panel. Log in again (flow 2) to continue.</p>
        <p class="step"><code>session.reresolveClaimsOnRefresh</code> now defaults to <code>true</code>: every refresh re-runs <code>resolveAuthContext</code>, so the decoded claims below show <code>claims.via: "refresh"</code> (this harness's hook tags the calling method).</p>
        <p class="step">These requests deliberately omit cookies (<code>credentials:'omit'</code>) and rely purely on the body-supplied token. Since 0.4.0 a token in the body wins over the refresh cookie anyway; omitting the cookie just keeps the check unambiguous.</p>
        <label>Refresh token</label>
        <input id="refreshToken">
        <button onclick="doRefresh()">Refresh</button>
        <button class="secondary" onclick="retryPrevious()">Retry with the PREVIOUS token (should now fail)</button>
        <pre id="result" class="result"></pre>
      </div>
      <div id="token-display"></div>

      <script>
        let previousToken = null;
        async function doRefresh() {
          const current = document.getElementById('refreshToken').value;
          const result = await callApi('${AUTH_PREFIX}/session/refresh', { method: 'POST', body: { refreshToken: current }, credentials: 'omit' });
          showResult('result', result);
          if (result.body?.refreshToken) {
            previousToken = current; // capture what we just spent, before overwriting the box
            document.getElementById('refreshToken').value = result.body.refreshToken;
            renderTokenPair('token-display', result.body);
          }
        }
        async function retryPrevious() {
          if (!previousToken) { alert('Do a successful refresh first so there is a "previous" token to retry.'); return; }
          const result = await callApi('${AUTH_PREFIX}/session/refresh', { method: 'POST', body: { refreshToken: previousToken }, credentials: 'omit' });
          showResult('result', result);
        }
      </script>`,
        }));
    });
}
