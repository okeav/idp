---
title: "Outbound Webhooks"
package: "@okeav/idp-core"
category: "api-reference"
tags: ["webhooks", "hmac", "events"]
description: "WebhookDispatcher, verifyWebhookSignature, delivery/retry mechanics, credential stripping, and the Stripe-style HMAC signature scheme."
---

# Outbound Webhooks

Additive to the in-process [event hooks](bootstrap-config.md#event-hooks-confighooks) — never a
replacement. When `config.webhooks.endpoints` is non-empty, every `onAuditLog`/named hook event
**also** gets POSTed as a signed JSON payload to each configured endpoint (subject to that
endpoint's `events` filter). `resolveAuthContext` is excluded (it's a data-returning callback, not
a one-way event).

## `config.webhooks`

```ts
{
  endpoints?: Array<{
    url: string;                  // https only (http only to localhost / 127.0.0.1 / [::1])
    secret: string;               // signing secret, at least 16 characters
    events?: string[];            // only these event names are sent here; default: all
    includeCredentials?: boolean; // default false — see "Credential fields" below
  }>;                             // default [] — disabled
  maxAttempts?: number;      // default 5
  retryBaseDelayMs?: number; // default 500 (doubles each attempt)
  timeoutMs?: number;        // default 5000
  maxInFlight?: number;      // default 100
}
```

Leave `endpoints` empty (the default) to disable entirely. Endpoints are validated at startup —
`initIdentityProvider()` throws for an invalid URL, a non-`https` URL to anything but a loopback
host, a `secret` under 16 characters, or an `events` value that isn't an array of strings.
Deliveries carry account data (emails, user ids), so they must not travel in clear text.

With `configFromEnv()`, `IDP_WEBHOOK_URL` + `IDP_WEBHOOK_SECRET` configure a single endpoint (with
no `events` filter and no `includeCredentials`).

## Credential fields

Three named hooks carry live credentials — whoever holds one can reset a password, log in, or
verify an address:

| Hook | Credential fields |
|---|---|
| `onPasswordResetRequested` | `resetToken` |
| `onMagicLinkRequested` | `magicLinkToken` |
| `onVerificationEmailRequested` | `verificationToken`, `verificationCode` |

These fields are **stripped** from deliveries to every endpoint unless it sets
`includeCredentials: true`. Set it only on the endpoint that actually sends those emails; an
analytics or audit receiver (and its logs and retry queues) should never be able to take over
accounts. The rest of the payload (e.g. `email`, `firstName`) is still delivered. Before 0.4.0
these fields went to every endpoint.

## Delivery mechanics

Each delivery is a **fire-and-forget background operation** — a webhook endpoint being slow,
erroring, or completely unreachable never blocks or fails the auth request that triggered it.
`WebhookDispatcher.dispatch(event, payload)` returns immediately (`void`, not a promise callers
await); failures are caught internally and only logged.

A delivery is dispatched **after the in-process hook settles** — and is still sent if that hook
throws, so one failing consumer callback doesn't drop the event for every receiver. (The request
itself waits for an in-process hook at most `config.hookTimeoutMs`, default 10 s; a hook still
running after that keeps running, and its delivery goes out when it finishes.) On the endpoints that
must not reveal whether an account exists — register, resend verification, forgot password,
magic-link request — the email hooks and their audit events are started but not awaited at all.

Failed deliveries retry with **exponential backoff**: `retryBaseDelayMs * 2^(attempt-1)` between
attempts, up to `maxAttempts` total tries, before being logged and dropped permanently — there is
no dead-letter queue or persisted retry state.

Each attempt is bounded by `timeoutMs`. A non-2xx response is treated as a failure and retried like
a network error — **including a 3xx**: redirects are never followed, so a signed body is never
re-sent to wherever a redirect points.

At most `maxInFlight` deliveries (each including its retries) run at once per process. Beyond that,
new events are **dropped** with a logged warning rather than queued without bound. Logged URLs
omit credentials and the query string.

## Request shape

```
POST <endpoint.url>
Content-Type: application/json
X-Idp-Event: <event name>
X-Idp-Delivery: <UUID, unique per delivery attempt *sequence*>
X-Idp-Signature: t=<unix seconds>,v1=<hex HMAC-SHA256>

{ "id": "3f0c…", "event": "LOGIN", "payload": { "action": "LOGIN", "userId": "...", "email": "...", "timestamp": "2026-01-01T00:00:00.000Z" }, "timestamp": "2026-01-01T00:00:00.001Z" }
```

- `id` — the delivery id, the same value as the `X-Idp-Delivery` header but **inside the signed
  body**. De-duplicate on the body's `id`: unlike the header, it can't be changed to pass a replayed
  delivery off as a new one.
- `payload` — for `onAuditLog`-sourced events, the *entire* hook argument passed through unchanged:
  it always carries its own `action` (duplicating the top-level `event`) and its own nested
  `timestamp` (distinct from, and slightly earlier than, the outer one). Named notification hooks
  (e.g. `onMagicLinkRequested`) don't have this `action`/nested-`timestamp` shape — `payload` there
  is just whatever fields that specific hook passes, minus any stripped credential fields.

Headers:

- `X-Idp-Event` — the event name. For `onAuditLog`-sourced events, this is `payload.action` (e.g.
  `LOGIN`, `REGISTERED`, `PASSWORD_CHANGED` — see the full action list in
  [Bootstrap & Config](bootstrap-config.md#event-hooks-confighooks)), which is more useful for
  filtering than the literal string `"onAuditLog"`. For named notification hooks, it's the hook
  name itself (e.g. `onMagicLinkRequested`). An endpoint's `events` list matches these same names.
- `X-Idp-Delivery` — a UUID generated once per **endpoint** per `dispatch()` call (shared across
  all retry attempts for that endpoint's delivery). If more than one endpoint is configured, each
  gets its own distinct delivery ID for the same logical event.
- `X-Idp-Signature` — Stripe-style: `t=<unix seconds>,v1=<hex HMAC-SHA256>`, computed over
  `` `${t}.${rawBody}` `` with the endpoint's configured `secret`. `t` is re-stamped on every
  retry attempt.

## `WebhookDispatcher`

```ts
class WebhookDispatcher {
  constructor(opts: { endpoints?; maxAttempts?; retryBaseDelayMs?; timeoutMs?; maxInFlight? }, logger?: Logger);
  readonly isNoop: boolean; // true when endpoints is empty
  dispatch(event: string, payload: unknown, opts?: { credentialFields?: string[] }): void; // fire-and-forget
}
```

Normally constructed once internally by `initIdentityProvider()` from `config.webhooks` — exported
for advanced use (e.g. dispatching your own application events through the same signed-delivery
mechanism). The constructor applies the same endpoint validation as startup (it throws on an
invalid endpoint). `opts.credentialFields` names payload fields to strip for endpoints without
`includeCredentials`.

## `verifyWebhookSignature(secret, rawBody, signatureHeader, opts?)`

```ts
function verifyWebhookSignature(
  secret: string | string[],
  rawBody: string,
  signatureHeader: string | undefined,
  opts?: { toleranceSeconds?: number } // default 300 (5 min)
): boolean
```

For consumers **receiving** webhook deliveries from this package. `rawBody` must be the exact,
unparsed request body string — **verify before you `JSON.parse`**, since the signature is computed
over the raw string. Rejects stale deliveries (`|now - t| > toleranceSeconds`) and compares HMACs
with `crypto.timingSafeEqual`.

**Rotation:** pass an array of secrets (e.g. `[current, previous]`) to accept a signature made with
any of them; the header may also carry several `v1=` signatures, and any one matching suffices.

Returns `false` (never throws) for: a missing/malformed header or non-string body, an unparseable
`t`, no well-formed `v1` (64 hex characters), a stale timestamp, no non-empty secret, or a
signature mismatch.

A valid signature doesn't stop a replay of the same delivery within the tolerance window — after
verifying, de-duplicate on the body's `id`.

## Related

- [Bootstrap & Config](bootstrap-config.md) — the full event-hooks table these deliveries wrap.
- [Verify HMAC Webhook Signature example](../examples/verify-hmac-webhook-signature.md)
