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
        <p class="step">This endpoint is configured <em>without</em> <code>includeCredentials</code>, so idp-core strips credential fields (<code>resetToken</code>, <code>magicLinkToken</code>, <code>verificationToken</code>/<code>verificationCode</code>) from its deliveries — the "credentials" column below should always read <code>stripped</code>. (Only the endpoint that actually sends your emails should set <code>includeCredentials: true</code>.) Note the password-reset delivery only fires for an existing account — register (and it needn't be verified) first.</p>
      </div>

      <div class="card">
        <p class="step">Received deliveries (polling <code>/api/webhook-deliveries</code> every 1.5s) — each row's signature is independently re-verified here using <code>verifyWebhookSignature()</code> server-side against the exact raw body this harness received.</p>
        <p class="step">"body id" is the signed <code>id</code> inside the delivery body (new in 0.4.0) — de-duplicate on that one; it matches the unsigned <code>X-Idp-Delivery</code> header.</p>
        <table id="deliveries-table"><tr><th>event</th><th>delivery id</th><th>body id</th><th>signature</th><th>credentials</th><th>received at</th></tr></table>
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
          table.innerHTML = '<tr><th>event</th><th>delivery id</th><th>body id</th><th>signature</th><th>credentials</th><th>received at</th></tr>' +
            deliveries.slice().reverse().map(d =>
              '<tr><td>' + escapeHtml(d.event) + '</td><td><code>' + escapeHtml((d.deliveryId||'').slice(0,8)) + '</code></td>' +
              '<td><code>' + escapeHtml(String(d.bodyId||'(none)').slice(0,8)) + '</code></td>' +
              '<td><span class="badge ' + (d.valid ? 'ok' : 'bad') + '">' + (d.valid ? 'VALID' : 'INVALID') + '</span></td>' +
              '<td>' + ((d.credentialFieldsPresent||[]).length ? '<span class="badge bad">present: ' + escapeHtml(d.credentialFieldsPresent.join(', ')) + '</span>' : '<span class="badge ok">stripped</span>') + '</td>' +
              '<td>' + new Date(d.receivedAt).toLocaleTimeString() + '</td></tr>'
            ).join('');
        }
        setInterval(pollDeliveries, 1500);
        document.addEventListener('DOMContentLoaded', pollDeliveries);
      </script>`,
        }));
    });
}
