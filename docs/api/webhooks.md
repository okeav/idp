---
title: "Outbound Webhooks"
package: "@okeav/idp-core"
category: "api-reference"
tags: ["webhooks", "hmac", "events"]
description: "WebhookDispatcher, verifyWebhookSignature, delivery/retry mechanics, and the Stripe-style HMAC signature scheme."
---

# Outbound Webhooks

Additive to the in-process [event hooks](bootstrap-config.md#event-hooks-confighooks) — never a
replacement. When `config.webhooks.endpoints` is non-empty, every `onAuditLog`/named hook event
**also** gets POSTed as a signed JSON payload to each configured endpoint.
`resolveAuthContext` is excluded (it's a data-returning callback, not a one-way event).

## `config.webhooks`

```ts
{
  endpoints?: Array<{ url: string; secret: string }>; // default [] — disabled
  maxAttempts?: number;      // default 5
  retryBaseDelayMs?: number; // default 500 (doubles each attempt)
  timeoutMs?: number;        // default 5000
}
```

Leave `endpoints` empty (the default) to disable entirely. Entries missing `url` or `secret` are
filtered out at construction time.

## Delivery mechanics

Each delivery is a **fire-and-forget background operation** — a webhook endpoint being slow,
erroring, or completely unreachable never blocks or fails the auth request that triggered it.
`WebhookDispatcher.dispatch(event, payload)` returns immediately (`void`, not a promise callers
await); failures are caught internally and only logged.

Failed deliveries retry with **exponential backoff**: `retryBaseDelayMs * 2^(attempt-1)` between
attempts, up to `maxAttempts` total tries, before being logged and dropped permanently — there is
no dead-letter queue or persisted retry state.

Each attempt is bounded by `timeoutMs` via `AbortController`; a non-2xx response is treated as a
failure and retried like a network error.

## Request shape

```
POST <endpoint.url>
Content-Type: application/json
X-Idp-Event: <event name>
X-Idp-Delivery: <UUID, unique per delivery attempt *sequence*>
X-Idp-Signature: t=<unix seconds>,v1=<hex HMAC-SHA256>

{ "event": "LOGIN", "payload": { "action": "LOGIN", "userId": "...", "email": "...", "timestamp": "2026-01-01T00:00:00.000Z" }, "timestamp": "2026-01-01T00:00:00.001Z" }
```

For `onAuditLog`-sourced events, `payload` is the *entire* hook argument passed through unchanged —
it always carries its own `action` (duplicating the top-level `event`) and its own nested
`timestamp` (distinct from, and slightly earlier than, the outer one). Named notification hooks
(e.g. `onMagicLinkRequested`) don't have this `action`/nested-`timestamp` shape — `payload` there is
just whatever fields that specific hook passes.

- `X-Idp-Event` — the event name. For `onAuditLog`-sourced events, this is `payload.action` (e.g.
  `LOGIN`, `REGISTERED`, `PASSWORD_CHANGED` — see the full action list in
  [Bootstrap & Config](bootstrap-config.md#event-hooks-confighooks)), which is more useful for
  filtering than the literal string `"onAuditLog"`. For named notification hooks, it's the hook
  name itself (e.g. `onMagicLinkRequested`).
- `X-Idp-Delivery` — a UUID generated once per **endpoint** per `dispatch()` call (shared across
  all retry attempts for that endpoint's delivery) — use it for dedup on your end. If more than one
  endpoint is configured, each gets its own distinct delivery ID for the same logical event.
- `X-Idp-Signature` — Stripe-style: `t=<unix seconds>,v1=<hex HMAC-SHA256>`, computed over
  `` `${t}.${rawBody}` `` with the endpoint's configured `secret`.

## `WebhookDispatcher`

```ts
class WebhookDispatcher {
  constructor(opts: { endpoints?; maxAttempts?; retryBaseDelayMs?; timeoutMs? }, logger?: Logger);
  readonly isNoop: boolean; // true when endpoints is empty
  dispatch(event: string, payload: unknown): void; // fire-and-forget
}
```

Normally constructed once internally by `initIdentityProvider()` from `config.webhooks` — exported
for advanced use (e.g. dispatching your own application events through the same signed-delivery
mechanism).

## `verifyWebhookSignature(secret, rawBody, signatureHeader, opts?)`

```ts
function verifyWebhookSignature(
  secret: string,
  rawBody: string,
  signatureHeader: string | undefined,
  opts?: { toleranceSeconds?: number } // default 300 (5 min)
): boolean
```

For consumers **receiving** webhook deliveries from this package. `rawBody` must be the exact,
unparsed request body bytes/string — **verify before you `JSON.parse`**, since the signature is
computed over the raw string. Rejects stale deliveries (`|now - t| > toleranceSeconds`) and uses
`crypto.timingSafeEqual` for the HMAC comparison (with a length check first, since
`timingSafeEqual` throws on mismatched buffer lengths rather than returning `false`).

Returns `false` (never throws) for: missing/malformed header, unparseable `t`/`v1` fields, stale
timestamp, or signature mismatch.

## Related

- [Bootstrap & Config](bootstrap-config.md) — the full event-hooks table these deliveries wrap.
- [Verify HMAC Webhook Signature example](../examples/verify-hmac-webhook-signature.md)
