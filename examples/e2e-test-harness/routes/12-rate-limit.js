import { layout } from '../lib/layout.js';

export function mountRateLimitFlow(app, { AUTH_PREFIX }) {
    app.get('/flows/rate-limit', (req, res) => {
        res.send(layout({
            title: '12. Rate limiting',
            body: `
      <div class="flag">This harness configures a deliberately low <code>rateLimiting.loginByEmail</code> threshold (max 5 per 5 minutes — production defaults are 5 per 15 minutes, see idp-core's README "Rate limiting") so you can trip it in a handful of clicks. Account lockout (<code>maxFailedLoginAttempts</code>) is set very high in this harness specifically so it doesn't interfere with what you're observing here — these are two independent mechanisms.</div>

      <div class="card">
        <p class="step">Fires sequential wrong-password login attempts against one fixed email. Watch for HTTP 401 (invalid credentials) turning into HTTP 429 (<code>RATE_LIMIT_EXCEEDED</code>) once the threshold trips.</p>
        <label>Email (doesn't need to be a real account — the per-email rate limit key is derived from the email regardless)</label>
        <input id="email" value="rate-limit-demo@example.com">
        <label>Number of attempts to fire</label>
        <input id="count" value="10" type="number">
        <button onclick="fire()">Fire attempts</button>
        <table id="attempts-table"><tr><th>#</th><th>status</th><th>error code</th></tr></table>
      </div>

      <script>
        async function fire() {
          const email = document.getElementById('email').value;
          const n = parseInt(document.getElementById('count').value, 10);
          const table = document.getElementById('attempts-table');
          table.innerHTML = '<tr><th>#</th><th>status</th><th>error code</th></tr>';
          for (let i = 1; i <= n; i++) {
            const result = await callApi('${AUTH_PREFIX}/login', { method: 'POST', body: { email, password: 'DefinitelyWrongPassword1!' } });
            const row = document.createElement('tr');
            const badgeClass = result.status === 429 ? 'bad' : (result.status === 401 ? 'ok' : '');
            row.innerHTML = '<td>' + i + '</td><td><span class="badge ' + (result.status === 429 ? 'bad' : 'ok') + '">' + result.status + '</span></td><td>' + (result.body?.error || '') + '</td>';
            table.appendChild(row);
          }
        }
      </script>`,
        }));
    });
}
