---
title: "Verify an Outbound Webhook's HMAC Signature"
package: "@okeav/idp-core"
category: "example"
tags: ["webhooks", "hmac", "express"]
description: "Configure a webhook endpoint and verify inbound deliveries with verifyWebhookSignature() on the exact raw request body."
---

# Verify an Outbound Webhook's HMAC Signature

A receiving endpoint for the deliveries idp-core sends when `config.webhooks.endpoints` is
configured. See [Outbound Webhooks](../api/webhooks.md) for the full delivery/retry mechanics.

## Prerequisites

- A running idp-core server.
- A second Express app (or route) to receive deliveries — this example runs it in the same
  process for simplicity, but it can be any HTTP endpoint you control.

## Configure the endpoint

```js
const WEBHOOK_SECRET = 'a-long-random-shared-secret';

await initIdentityProvider({
  // ...
  webhooks: {
    endpoints: [{ url: 'http://localhost:3000/webhooks/receiver', secret: WEBHOOK_SECRET }],
    maxAttempts: 5,       // default
    retryBaseDelayMs: 500, // default — doubles each retry
    timeoutMs: 5000,       // default
  },
});
```

Every `onAuditLog` event (e.g. `LOGIN`, `REGISTERED`, `PASSWORD_CHANGED`) and every named
notification hook (`onMagicLinkRequested`, etc.) now **also** gets POSTed here, in addition to
whatever your in-process `hooks` callbacks already do.

## Receive and verify

**The signature is computed over the exact raw request body bytes — verify before you
`JSON.parse`.** Mount a raw-body parser scoped to this one route, not the global JSON parser.

```js
import express from 'express';
import { verifyWebhookSignature } from '@okeav/idp-core';

const app = express();

app.post(
  '/webhooks/receiver',
  express.raw({ type: 'application/json' }), // req.body is a Buffer here, NOT parsed JSON
  (req, res) => {
    const rawBody = req.body.toString('utf8');
    const signatureHeader = req.header('X-Idp-Signature'); // "t=<unix seconds>,v1=<hex hmac>"

    const valid = verifyWebhookSignature(WEBHOOK_SECRET, rawBody, signatureHeader);
    if (!valid) {
      return res.status(400).json({ error: 'invalid signature' });
    }

    const { event, payload, timestamp } = JSON.parse(rawBody);
    console.log(`[webhook] ${event} at ${timestamp}`, payload);
    // event is req.header('X-Idp-Event') too — same value, in the header for
    // routing without parsing the body if you want that.

    res.status(200).json({ received: true }); // any non-2xx triggers a retry
  }
);
```

## Notes

- **Idempotency**: `X-Idp-Delivery` is a UUID shared across all retry attempts for one logical
  delivery — dedupe on it if your handler isn't naturally idempotent.
- **Replay protection**: `verifyWebhookSignature` rejects deliveries older than
  `opts.toleranceSeconds` (default 300s) even with a valid signature — pass a custom tolerance if
  your infrastructure has unusually high latency:
  ```js
  verifyWebhookSignature(secret, rawBody, signatureHeader, { toleranceSeconds: 600 });
  ```
- **Never blocks the auth request**: a slow or erroring webhook endpoint never fails or delays the
  login/register/etc. call that triggered it — deliveries are fire-and-forget with exponential
  backoff, logged and dropped after `maxAttempts`.
- **Mount order matters**: if your app also uses `express.json()` globally, mount the webhook
  route (with its own `express.raw()`) **before** the global JSON parser, or scope the raw parser
  to just this path as shown above — a body already consumed by `express.json()` won't be
  available as a raw string here.

## Related

- [Outbound Webhooks](../api/webhooks.md) — full request shape, headers, and retry semantics.
- [Bootstrap & Config](../api/bootstrap-config.md) — the underlying event-hooks table these
  deliveries mirror.
