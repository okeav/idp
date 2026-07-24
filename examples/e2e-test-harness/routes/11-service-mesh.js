import crypto from 'crypto';
import { initServiceIdentity, mintServiceToken, verifyServiceTokenRemote } from '@okeav/idp-core';
import { layout } from '../lib/layout.js';

function generateKeypair() {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    return { privateKey, publicKey };
}

export function mountServiceMeshFlow(app, { IDP_BASE_URL, BOOTSTRAP_SECRET }) {
    app.get('/flows/service-mesh', (req, res) => {
        res.send(layout({
            title: '11. Service mesh (S2S JWKS trust)',
            body: `
      <div class="flag">
        <code>initServiceIdentity()</code>'s "which service am I" identity is a client-side singleton (one active identity per process — realistic, since a real backend service really does have exactly one identity). So this page registers Service A, then Service B (which becomes the "current" identity), then mints a token AS B targeting A — all through the real, unmodified public API, done sequentially rather than concurrently.
      </div>

      <div class="card">
        <p class="step">Step 1 — register "harness-service-a" (generates a fresh RSA keypair server-side, publishes the public key via <code>/internal/service-keys</code>).</p>
        <button onclick="register('harness-service-a')">Register Service A</button>
        <pre id="register-a-result" class="result"></pre>
      </div>

      <div class="card">
        <p class="step">Step 2 — register "harness-service-b" (this becomes the active identity — A's public key stays registered server-side regardless).</p>
        <button onclick="register('harness-service-b')">Register Service B</button>
        <pre id="register-b-result" class="result"></pre>
      </div>

      <div class="card">
        <p class="step">Step 3 — mint an S2S token as B, audience = A.</p>
        <button onclick="mint()">Mint token (B → A)</button>
        <pre id="mint-result" class="result"></pre>
      </div>

      <div class="card">
        <p class="step">Step 4 — verify it against the remote services-JWKS endpoint (this doesn't depend on which identity is "active" — it looks the key up by <code>kid</code>).</p>
        <button onclick="verify()">Verify token</button>
        <pre id="verify-result" class="result"></pre>
      </div>

      <div class="card">
        <p class="step">Step 5 — fetch the raw JWKS — confirm both services' keys are present.</p>
        <button onclick="fetchJwks()">GET /.well-known/services-jwks.json</button>
        <pre id="jwks-result" class="result"></pre>
      </div>

      <script>
        let lastToken = null;
        async function register(name) {
          const result = await callApi('/api/service-mesh/register', { method: 'POST', body: { name } });
          showResult(name === 'harness-service-a' ? 'register-a-result' : 'register-b-result', result);
        }
        async function mint() {
          const result = await callApi('/api/service-mesh/mint', { method: 'POST', body: { audience: 'harness-service-a', scopes: ['test:read'] } });
          showResult('mint-result', result);
          if (result.body?.token) lastToken = result.body.token;
        }
        async function verify() {
          if (!lastToken) { alert('Mint a token first.'); return; }
          const result = await callApi('/api/service-mesh/verify', { method: 'POST', body: { token: lastToken, expectedAud: 'harness-service-a' } });
          showResult('verify-result', result);
        }
        async function fetchJwks() {
          const result = await callApi('${IDP_BASE_URL}/.well-known/services-jwks.json');
          showResult('jwks-result', result);
        }
      </script>`,
        }));
    });

    app.post('/api/service-mesh/register', async (req, res) => {
        try {
            const { name } = req.body;
            const { privateKey } = generateKeypair();
            const result = await initServiceIdentity({ serviceName: name, privateKeyPem: privateKey, idpBaseUrl: IDP_BASE_URL, bootstrapSecret: BOOTSTRAP_SECRET });
            res.json({ serviceName: name, kid: result.kid });
        } catch (err) {
            res.status(500).json({ error: err.message });
        }
    });

    app.post('/api/service-mesh/mint', (req, res) => {
        try {
            const { audience, scopes } = req.body;
            const token = mintServiceToken(audience, { scopes: scopes || [] });
            res.json({ token });
        } catch (err) {
            res.status(500).json({ error: err.message });
        }
    });

    app.post('/api/service-mesh/verify', async (req, res) => {
        try {
            const { token, expectedAud } = req.body;
            const payload = await verifyServiceTokenRemote(token, { expectedAud, idpBaseUrl: IDP_BASE_URL });
            res.json({ verified: true, payload });
        } catch (err) {
            res.status(400).json({ verified: false, error: err.message });
        }
    });
}
