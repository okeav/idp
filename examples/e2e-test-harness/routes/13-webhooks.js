import { layout } from '../lib/layout.js';

export function mountWebhooksFlow(app, { AUTH_PREFIX, BASE_URL, WEBHOOK_SECRET }) {
    app.get('/flows/webhooks', (req, res) => {
        res.send(layout({
            title: '13. Outbound webhooks',
            body: `
      <div class="flag">Pre-configured at boot (see <code>server.js</code>'s <code>config.webhooks</code>) pointing at this same process's own <code>POST /webhooks/receiver</code> — that's the realistic way to test this, since webhook endpoints are deploy-time config in idp-core, not something registered through a runtime API.
      <br><br>
      Endpoint: <code>${BASE_URL}/webhooks/receiver</code> &nbsp; Secret: <code>${WEBHOOK_SECRET}</code></div>

      <div class="card">
        <p class="step">Trigger a few events that fire hooks (each of these also appears in the activity panel — watch both at once). A failed login still fires <code>onAuditLog</code> only on success paths, so use register/login/password-reset for guaranteed deliveries.</p>
        <label>Email</label>
        <input id="email" value="webhook-demo-${Date.now()}@example.com">
        <button onclick="doRegister()">Register (fires REGISTERED)</button>
        <button onclick="doForgot()">Request password reset (fires onPasswordResetRequested)</button>
      </div>

      <div class="card">
        <p class="step">Received deliveries (polling <code>/api/webhook-deliveries</code> every 1.5s) — each row's signature is independently re-verified here using <code>verifyWebhookSignature()</code> server-side against the exact raw body this harness received.</p>
        <table id="deliveries-table"><tr><th>event</th><th>delivery id</th><th>signature</th><th>received at</th></tr></table>
      </div>

      <script>
        async function doRegister() {
          const email = document.getElementById('email').value;
          await callApi('${AUTH_PREFIX}/register', { method: 'POST', body: { email, password: 'Str0ng!Passw0rd' } });
        }
        async function doForgot() {
          const email = document.getElementById('email').value;
          await callApi('${AUTH_PREFIX}/password/forgot', { method: 'POST', body: { email } });
        }
        async function pollDeliveries() {
          const res = await fetch('/api/webhook-deliveries');
          const deliveries = await res.json();
          const table = document.getElementById('deliveries-table');
          table.innerHTML = '<tr><th>event</th><th>delivery id</th><th>signature</th><th>received at</th></tr>' +
            deliveries.slice().reverse().map(d =>
              '<tr><td>' + d.event + '</td><td><code>' + (d.deliveryId||'').slice(0,8) + '</code></td>' +
              '<td><span class="badge ' + (d.valid ? 'ok' : 'bad') + '">' + (d.valid ? 'VALID' : 'INVALID') + '</span></td>' +
              '<td>' + new Date(d.receivedAt).toLocaleTimeString() + '</td></tr>'
            ).join('');
        }
        setInterval(pollDeliveries, 1500);
        document.addEventListener('DOMContentLoaded', pollDeliveries);
      </script>`,
        }));
    });
}
