// Shared helpers loaded on every page — request/response display, JWT
// decoding, and the polling "recent activity" panel.

async function callApi(url, opts = {}) {
  const res = await fetch(url, {
    method: opts.method || 'GET',
    headers: { ...(opts.body ? { 'Content-Type': 'application/json' } : {}), ...(opts.headers || {}) },
    body: opts.body ? JSON.stringify(opts.body) : undefined,
    // Same-origin fetch sends cookies by default. Most pages want that (they
    // rely on the login cookie for authContextMiddleware) — but a page that's
    // specifically testing a *body-supplied* token (see /flows/refresh) needs
    // to opt out, since the server prefers the cookie over the body when both
    // are present (COOKIE_NAMES.REFRESH_TOKEN in idp-core's refreshTokenHandler).
    credentials: opts.credentials || 'same-origin',
  });
  let body;
  const text = await res.text();
  try { body = text ? JSON.parse(text) : null; } catch { body = text; }
  return { status: res.status, ok: res.ok, body };
}

function showResult(el, result) {
  const target = typeof el === 'string' ? document.getElementById(el) : el;
  target.className = 'result ' + (result.ok ? '' : 'err');
  target.textContent = `HTTP ${result.status}\n\n` + JSON.stringify(result.body, null, 2);
}

// Decodes a JWT's header/payload for on-screen display only — no signature
// verification happens client-side, this is purely "what does the token say."
function decodeJwt(token) {
  try {
    const [h, p] = token.split('.');
    const pad = (s) => s + '==='.slice((s.length + 3) % 4);
    const dec = (s) => JSON.parse(atob(pad(s).replace(/-/g, '+').replace(/_/g, '/')));
    return { header: dec(h), payload: dec(p) };
  } catch (err) {
    return { error: 'Could not decode: ' + err.message };
  }
}

function renderTokenPair(elId, { accessToken, refreshToken, accessTokenExpiresAt, refreshTokenExpiresAt, ...rest }) {
  const el = document.getElementById(elId);
  const decoded = accessToken ? decodeJwt(accessToken) : null;
  el.innerHTML = `
    <div class="card">
      <strong>Access token</strong> (expires ${accessTokenExpiresAt || '?'})
      <pre class="result">${accessToken || '(none)'}</pre>
      <strong>Decoded claims</strong>
      <pre class="result">${decoded ? JSON.stringify(decoded.payload, null, 2) : '(n/a)'}</pre>
      <strong>Refresh token</strong> (expires ${refreshTokenExpiresAt || '?'})
      <pre class="result">${refreshToken || '(none)'}</pre>
      ${Object.keys(rest).length ? `<strong>Other fields</strong><pre class="result">${JSON.stringify(rest, null, 2)}</pre>` : ''}
    </div>`;
}

// ── Recent activity panel (polled, not pushed — keeps this dependency-free) ──
let _lastActivityId = 0;
async function pollActivity() {
  try {
    const res = await fetch(`/api/activity?since=${_lastActivityId}`);
    const entries = await res.json();
    if (entries.length === 0) return;
    const panel = document.getElementById('activity-panel');
    for (const e of entries) {
      _lastActivityId = Math.max(_lastActivityId, e.id);
      const div = document.createElement('div');
      div.className = 'activity-item';
      const time = new Date(e.at).toLocaleTimeString();
      div.innerHTML = `<span class="kind ${e.kind}">${e.kind}</span><span class="label">${e.label}</span> <span class="at">${time}</span>` +
        (e.detail ? `<pre>${escapeHtml(typeof e.detail === 'string' ? e.detail : JSON.stringify(e.detail))}</pre>` : '');
      panel.prepend(div);
    }
    // cap DOM nodes so a long session doesn't grow unbounded
    while (panel.children.length > 150) panel.removeChild(panel.lastChild);
  } catch {
    // harness server not reachable yet / page navigating — ignore, next poll will retry
  }
}
function escapeHtml(s) {
  return String(s).replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));
}
setInterval(pollActivity, 1500);
document.addEventListener('DOMContentLoaded', pollActivity);
