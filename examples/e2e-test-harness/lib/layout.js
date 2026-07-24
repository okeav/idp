export const FLOWS = [
    { path: '/flows/register', label: '1. Register + verify' },
    { path: '/flows/login', label: '2. Login (password)' },
    { path: '/flows/refresh', label: '3. Refresh rotation' },
    { path: '/flows/sessions', label: '4. Logout / logout-all' },
    { path: '/flows/password-reset', label: '5. Forgot / reset password' },
    { path: '/flows/mfa', label: '6. MFA (TOTP)' },
    { path: '/flows/magic-link', label: '7. Magic link' },
    { path: '/flows/webauthn', label: '8. WebAuthn / passkeys' },
    { path: '/flows/oauth2', label: '9. OAuth2 / OIDC' },
    { path: '/flows/sso', label: '10. SSO' },
    { path: '/flows/service-mesh', label: '11. Service mesh' },
    { path: '/flows/rate-limit', label: '12. Rate limiting' },
    { path: '/flows/webhooks', label: '13. Webhooks' },
];

export function layout({ title, body, extraScripts = [] }) {
    return `<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>${title} — idp-core test harness</title>
  <link rel="stylesheet" href="/style.css">
</head>
<body>
  <header>
    <span class="brand">idp-core test harness</span>
    <a href="/">Index</a>
    ${FLOWS.map((f) => `<a href="${f.path}">${f.label}</a>`).join('\n    ')}
  </header>
  <div class="layout">
    <main>
      <h1>${title}</h1>
      ${body}
    </main>
    <aside>
      <h3>Recent activity (hooks + webhooks)</h3>
      <div id="activity-panel"></div>
    </aside>
  </div>
  <script src="/harness.js"></script>
  ${extraScripts.map((src) => `<script src="${src}"></script>`).join('\n  ')}
</body>
</html>`;
}
