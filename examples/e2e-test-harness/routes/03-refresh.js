import { layout } from '../lib/layout.js';

export function mountRefreshFlow(app, { AUTH_PREFIX }) {
    app.get('/flows/refresh', (req, res) => {
        res.send(layout({
            title: '3. Refresh token rotation',
            body: `
      <div class="card">
        <p class="step">Paste the <code>refreshToken</code> value from <a href="/flows/login">2. Login</a> (or any active session) below.
        Every successful refresh <strong>rotates</strong> the refresh token — the old value is revoked immediately, even though it hasn't expired.</p>
        <p class="step">These requests deliberately omit cookies (<code>credentials:'omit'</code>) and rely purely on the body-supplied token — <code>refreshTokenHandler</code> prefers the <code>refresh_token</code> cookie over the body when both are present, which would otherwise mask the "old token now fails" check with whatever your login cookie currently holds.</p>
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
          const result = await callApi('${AUTH_PREFIX}/refresh', { method: 'POST', body: { refreshToken: current }, credentials: 'omit' });
          showResult('result', result);
          if (result.body?.refreshToken) {
            previousToken = current; // capture what we just spent, before overwriting the box
            document.getElementById('refreshToken').value = result.body.refreshToken;
            renderTokenPair('token-display', result.body);
          }
        }
        async function retryPrevious() {
          if (!previousToken) { alert('Do a successful refresh first so there is a "previous" token to retry.'); return; }
          const result = await callApi('${AUTH_PREFIX}/refresh', { method: 'POST', body: { refreshToken: previousToken }, credentials: 'omit' });
          showResult('result', result);
        }
      </script>`,
        }));
    });
}
