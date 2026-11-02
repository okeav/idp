import crypto from 'crypto';
import { initServiceIdentity, mintServiceToken, verifyServiceTokenRemote } from '@okeav/idp-core';
import { layout } from '../lib/layout.js';

function generateKeypair() {
    // RSA, >= 2048 bits — idp-core refuses anything weaker (and any private key PEM).
    const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    return { privateKey, publicKey };
}

export function mountServiceMeshFlow(app, { BASE_URL, IDP_BASE_URL, SERVICE_BOOTSTRAP_SECRETS, SHARED_BOOTSTRAP_SECRET, LEGACY_SERVICE_NAME }) {
    app.get('/flows/service-mesh', (req, res) => {
        res.send(layout({
            title: '11. Service mesh (S2S JWKS trust)',
            body: `
      <div class="flag">
        <code>initServiceIdentity()</code>'s "which service am I" identity is a client-side singleton (one active identity per process — realistic, since a real backend service really does have exactly one identity). So this page registers Service A, then Service B (which becomes the "current" identity), then mints a token AS B targeting A — all through the real, unmodified public API, done sequentially rather than concurrently.
        <br><br>
        Each service registers with <strong>its own</strong> bootstrap secret (<code>serviceMesh.bootstrapSecrets</code> in <code>server.js</code>), which covers only that service's name — so clicking a Register button again simply <em>rotates</em> that service's key (the previous one goes <code>ROTATING</code> — still verifying for <code>serviceMesh.rotationGraceSeconds</code>, default 1 hour — then <code>RETIRED</code> on the next rotation). Names must match <code>^[a-z0-9][a-z0-9-]{0,62}$</code> and are limited by <code>serviceMesh.allowedServiceNames</code> to the two below plus <code>${LEGACY_SERVICE_NAME}</code> (step 7). A key revoked with <code>revokeServiceKey()</code> is never re-activated: re-registering it answers <code>409 SERVICE_KEY_REVOKED</code> (the Register buttons always generate a fresh keypair, so they don't hit that).
      </div>

      <div class="card">
        <p class="step">Step 1 — register "harness-service-a" (generates a fresh RSA-2048 keypair server-side, publishes the public key via <code>/internal/service-keys</code>).</p>
        <button onclick="register('harness-service-a')">Register Service A</button>
        <pre id="register-a-result" class="result"></pre>
      </div>

      <div class="card">
        <p class="step">Step 2 — register "harness-service-b" (this becomes the active identity — A's public key stays registered server-side regardless).</p>
        <button onclick="register('harness-service-b')">Register Service B</button>
        <pre id="register-b-result" class="result"></pre>
      </div>

      <div class="card">
        <p class="step">Step 3 — mint an S2S token as B, audience = A (60-second lifetime; tokens without <code>exp</code> or living over 5 minutes are refused).</p>
        <button onclick="mint()">Mint token (B → A)</button>
        <pre id="mint-result" class="result"></pre>
      </div>

      <div class="card">
        <p class="step">Step 4 — verify it against the remote services-JWKS endpoint (this doesn't depend on which identity is "active" — it looks the key up by <code>kid</code>). The remote lookup caches the JWKS and force-refreshes on an unknown <code>kid</code> at most every 30 s — so if you re-register (rotate) B and verify within 30 s of the last fetch, wait a moment and retry.</p>
        <button onclick="verify()">Verify token</button>
        <pre id="verify-result" class="result"></pre>
      </div>

      <div class="card">
        <p class="step">Step 5 — fetch the raw JWKS — confirm both services' keys are present (with their <code>status</code>).</p>
        <button onclick="fetchJwks()">GET /.well-known/services-jwks.json</button>
        <pre id="jwks-result" class="result"></pre>
      </div>

      <div class="card">
        <p class="step">Step 6 — call an internal endpoint owned by Service A (<code>GET /internal-demo/service-a/whoami</code>), protected in-process by <code>serviceContextMiddleware()</code> (expects <code>aud</code> = <code>serviceMesh.ownServiceName</code>, here <code>harness-service-a</code>) and <code>requireServiceCallerMiddleware('harness-service-b')</code>. With B's token → 200 and <code>caller.name: harness-service-b</code>; with no token → 401.</p>
        <button onclick="callA(true)">Call as B (with token)</button>
        <button class="secondary" onclick="callA(false)">Call without a token</button>
        <pre id="call-result" class="result"></pre>
      </div>

      <div class="card">
        <p class="step">Step 7 — impersonation checks with only the <strong>shared</strong> <code>serviceMesh.bootstrapSecret</code>, which proves "some participating service", not which one.</p>
        <p class="step">7a — try to register a <em>new</em> key under "harness-service-a". Expected: <code>403 FORBIDDEN</code> — a name listed in <code>serviceMesh.bootstrapSecrets</code> registers only with its own secret, never the shared one (otherwise, once A's key was revoked, anyone with the shared secret could claim A's name).</p>
        <button class="danger" onclick="hijack('harness-service-a', 'hijack-result')">Register a key for A with the shared secret</button>
        <pre id="hijack-result" class="result"></pre>
        <p class="step">7b — register "${LEGACY_SERVICE_NAME}" (allowed, but with no per-service secret) with the shared secret, then click again: each click sends a brand-new key. Expected: <code>201</code> the first time the name has no key, then <code>409 SERVICE_NAME_TAKEN</code> — the shared secret can claim a name with no key yet, never replace an existing one. (Mongo persists across restarts, so after the first run every click is 409.)</p>
        <button class="danger" onclick="hijack('${LEGACY_SERVICE_NAME}', 'legacy-result')">Register ${LEGACY_SERVICE_NAME} with the shared secret</button>
        <pre id="legacy-result" class="result"></pre>
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
        async function callA(withToken) {
          const result = await callApi('/api/service-mesh/call-a', { method: 'POST', body: { withToken } });
          showResult('call-result', result);
        }
        async function hijack(name, resultId) {
          const result = await callApi('/api/service-mesh/register-shared', { method: 'POST', body: { name } });
          showResult(resultId, result);
        }
      </script>`,
        }));
    });

    // Registers with the service's OWN bootstrap secret (rotation allowed for that name only).
    app.post('/api/service-mesh/register', async (req, res) => {
        try {
            const { name } = req.body;
            const bootstrapSecret = Object.hasOwn(SERVICE_BOOTSTRAP_SECRETS, name) ? SERVICE_BOOTSTRAP_SECRETS[name] : null;
            if (!bootstrapSecret) return res.status(400).json({ error: `No bootstrap secret configured for '${name}'` });
            const { privateKey } = generateKeypair();
            const result = await initServiceIdentity({ serviceName: name, privateKeyPem: privateKey, idpBaseUrl: IDP_BASE_URL, bootstrapSecret });
            res.json({ serviceName: name, kid: result.kid });
        } catch (err) {
            res.status(500).json({ error: err.message });
        }
    });

    // Talks to /internal/service-keys directly (not through initServiceIdentity,
    // which would also switch this process's identity) with only the shared
    // secret and a brand-new key, to show the 403 / 409.
    app.post('/api/service-mesh/register-shared', async (req, res) => {
        try {
            const { name } = req.body;
            const { publicKey } = generateKeypair();
            const r = await fetch(`${IDP_BASE_URL}/internal/service-keys`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'x-s2s-bootstrap-secret': SHARED_BOOTSTRAP_SECRET },
                body: JSON.stringify({ name, publicKey: Buffer.from(publicKey, 'utf8').toString('base64') }),
            });
            res.status(r.status).json(await r.json().catch(() => null));
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

    // Plays "service B calling service A": mints a fresh token as the current
    // identity (B, after step 2) with aud = A, and calls A's protected route.
    app.post('/api/service-mesh/call-a', async (req, res) => {
        try {
            const headers = {};
            if (req.body?.withToken) headers.Authorization = `Bearer ${mintServiceToken('harness-service-a', { scopes: ['test:read'] })}`;
            const r = await fetch(`${BASE_URL}/internal-demo/service-a/whoami`, { headers });
            res.status(r.status).json(await r.json().catch(() => null));
        } catch (err) {
            res.status(500).json({ error: err.message });
        }
    });
}
