import { layout } from '../lib/layout.js';

export function mountSessionsFlow(app, { AUTH_PREFIX }) {
    app.get('/flows/sessions', (req, res) => {
        res.send(layout({
            title: '4. Logout (single session) / Logout all',
            body: `
      <div class="flag">Requires an active login cookie — do <a href="/flows/login">2. Login</a> first (in this same browser). Log in more than once (or refresh a few times) and you'll see multiple sessions listed below.</div>

      <div class="card">
        <p class="step">List your active sessions.</p>
        <button onclick="list()">List my sessions</button>
        <div id="sessions-table"></div>
      </div>

      <div class="card">
        <p class="step">Revoke ONE session by ID (pick one from the table above that is <em>not</em> necessarily your current one) — shows the before/after without logging your current browser session out.</p>
        <label>Session ID</label>
        <input id="sessionId">
        <button onclick="revokeOne()">Revoke this session</button>
        <pre id="revoke-one-result" class="result"></pre>
      </div>

      <div class="card">
        <p class="step">Logout (uses the <code>refresh_token</code> cookie automatically — this ends YOUR current browser session, so "list sessions" will 401 right after, which is correct: you have no valid cookie anymore).</p>
        <button class="danger" onclick="logout()">Logout (this session)</button>
        <pre id="logout-result" class="result"></pre>
      </div>

      <div class="card">
        <p class="step">Logout all — revokes every session for this user, including the current one. Log back in via flow 2 afterward to keep testing other flows.</p>
        <button class="danger" onclick="logoutAll()">Logout all</button>
        <pre id="logout-all-result" class="result"></pre>
      </div>

      <script>
        async function list() {
          const result = await callApi('${AUTH_PREFIX}/me/sessions');
          const el = document.getElementById('sessions-table');
          if (!result.ok) { el.innerHTML = '<pre class="result err">HTTP ' + result.status + '\\n' + JSON.stringify(result.body, null, 2) + '</pre>'; return; }
          el.innerHTML = '<table><tr><th>id</th><th>ip</th><th>device</th><th>createdAt</th><th>expiresAt</th></tr>' +
            result.body.map(s => \`<tr><td><code>\${s.id}</code></td><td>\${s.ipAddress||''}</td><td>\${(s.deviceInfo||'').slice(0,40)}</td><td>\${s.createdAt}</td><td>\${s.expiresAt}</td></tr>\`).join('') +
            '</table>';
        }
        async function revokeOne() {
          const id = document.getElementById('sessionId').value;
          const result = await callApi('${AUTH_PREFIX}/me/sessions/' + id, { method: 'DELETE' });
          showResult('revoke-one-result', result);
          list();
        }
        async function logout() {
          const result = await callApi('${AUTH_PREFIX}/logout', { method: 'POST', body: {} });
          showResult('logout-result', result);
        }
        async function logoutAll() {
          const result = await callApi('${AUTH_PREFIX}/logout/all', { method: 'POST' });
          showResult('logout-all-result', result);
        }
      </script>`,
        }));
    });
}
