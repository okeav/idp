import { layout, FLOWS } from '../lib/layout.js';
import { mountRegisterFlow } from './01-register.js';
import { mountLoginFlow } from './02-login.js';
import { mountRefreshFlow } from './03-refresh.js';
import { mountSessionsFlow } from './04-sessions.js';
import { mountPasswordResetFlow } from './05-password-reset.js';
import { mountMfaFlow } from './06-mfa.js';
import { mountMagicLinkFlow } from './07-magic-link.js';
import { mountWebauthnFlow } from './08-webauthn.js';
import { mountOAuth2Flow } from './09-oauth2.js';
import { mountSsoFlow } from './10-sso.js';
import { mountServiceMeshFlow } from './11-service-mesh.js';
import { mountRateLimitFlow } from './12-rate-limit.js';
import { mountWebhooksFlow } from './13-webhooks.js';

export function mountFlowRoutes(app, ctx) {
    app.get('/', (req, res) => {
        res.send(layout({
            title: 'idp-core end-to-end test harness',
            body: `
      <p>Click through each flow below, roughly in order (later flows assume you're logged in from flow 2, or that you've enabled MFA in flow 6, etc. — see README.md's checklist for exact prerequisites per flow). The panel on the right shows every hook and webhook delivery firing in real time as you go.</p>
      <ul class="checklist">
        ${FLOWS.map((f) => `<li><a href="${f.path}">${f.label}</a></li>`).join('\n        ')}
      </ul>
      <p>Full checklist with expected outcomes for each flow: see <code>README.md</code> in this folder.</p>`,
        }));
    });

    mountRegisterFlow(app, ctx);
    mountLoginFlow(app, ctx);
    mountRefreshFlow(app, ctx);
    mountSessionsFlow(app, ctx);
    mountPasswordResetFlow(app, ctx);
    mountMfaFlow(app, ctx);
    mountMagicLinkFlow(app, ctx);
    mountWebauthnFlow(app, ctx);
    mountOAuth2Flow(app, ctx);
    mountSsoFlow(app, ctx);
    mountServiceMeshFlow(app, ctx);
    mountRateLimitFlow(app, ctx);
    mountWebhooksFlow(app, ctx);
}
