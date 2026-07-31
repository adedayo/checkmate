# Spec: Webhooks

**Change:** 001-clean-slate-platform
**Status:** Draft

## Overview

Webhooks provide push notifications when significant events occur in CheckMate — scan completions, new findings, and exception changes. Each webhook registration specifies a target URL and a set of event types to subscribe to. Payloads are signed with HMAC-SHA256 for verification.

## Data Model

Webhooks are stored in the `webhooks` table:

| Field | Type | Description |
|-------|------|-------------|
| `id` | TEXT (PK) | Prefixed `wh_` + 12-char UUID fragment |
| `url` | TEXT | HTTPS endpoint to receive POST payloads |
| `events` | JSON | Array of subscribed event type strings |
| `secret_hash` | TEXT | bcrypt hash of the HMAC signing secret |
| `created_at` | TEXT | RFC 3339 timestamp |
| `last_delivered_at` | TEXT | RFC 3339 timestamp of last successful delivery |

## Event Types

| Event | Fired When |
|-------|------------|
| `scan.completed` | A scan finishes (status → `complete` or `failed`) |
| `finding.detected` | A new finding is detected during a scan |
| `exception.created` | A new exception is created |
| `exception.revoked` | An exception is revoked |

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/v1/webhooks` | List all registered webhooks (secrets redacted) |
| `POST` | `/v1/webhooks` | Register a new webhook |
| `DELETE` | `/v1/webhooks/{webhookId}` | Delete a webhook |
| `POST` | `/v1/webhooks/{webhookId}/test` | Send a test event to the webhook URL |

### Create Request

```json
{
  "url": "https://example.com/checkmate-events",
  "events": ["scan.completed", "finding.detected"]
}
```

Both `url` and `events` are required. The server generates a 32-byte random HMAC signing secret, returns it once in the response, and stores only the bcrypt hash.

### Create Response

```json
{
  "id": "wh_a1b2c3d4e5f6",
  "url": "https://example.com/checkmate-events",
  "events": ["scan.completed", "finding.detected"],
  "secret": "64-char-hex-encoded-secret",
  "createdAt": "2025-07-31T12:00:00Z"
}
```

> **The `secret` is shown only once at creation time.** It is never returned by `GET /v1/webhooks` or any other endpoint.

### List Response

The `secret` field is always empty in list responses for security.

### Test Endpoint

`POST /v1/webhooks/{webhookId}/test` dispatches a synthetic test event to the webhook URL. Returns `202 Accepted` immediately.

## Payload Delivery

When an event fires, CheckMate sends an HTTP POST to each registered webhook URL whose `events` array contains the event type.

### Payload Format

```json
{
  "event": "scan.completed",
  "timestamp": "2025-07-31T12:05:00Z",
  "data": { ... }
}
```

The `data` field contains event-specific information:

- **`scan.completed`:** `{ projectId, scanId, status, totalFindings, duration }`
- **`finding.detected`:** `{ findingId, secretType, severity, file, line }`
- **`exception.created`:** `{ exceptionId, ruleId, scopeType, reason }`
- **`exception.revoked`:** `{ exceptionId, ruleId }`

### HMAC Signature

Each delivery includes an `X-CheckMate-Signature` header containing `sha256=<hex-encoded HMAC-SHA256>` computed over the raw JSON body using the webhook's signing secret. Consumers should verify this signature to authenticate the payload.

## Security

- Signing secrets are generated using `crypto/rand` (32 bytes, hex-encoded to 64 chars).
- Only the bcrypt hash of the secret is persisted — CheckMate never stores the plaintext after the creation response.
- Webhook URLs should use HTTPS in production.

## Deferred

- **Retry with exponential backoff:** Failed deliveries are not currently retried. A retry queue with configurable backoff will be added.
- **Delivery log:** Recording delivery attempts, response codes, and latency for observability.
- **IP allowlisting:** Restricting webhook registration to known callback domains.
