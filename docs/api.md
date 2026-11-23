# CheckMate REST API (v1)

The CheckMate Platform offers a fully featured REST API, enabling integrations with CI/CD pipelines, custom dashboards, and external workflows.

## Base URL
All API requests must be prefixed with:
`/v1`

## Authentication
Authentication is handled via JWT Bearer tokens or API Keys. Include the token in the `Authorization` header of your HTTP requests:
`Authorization: Bearer <your_token>`

### 1. `POST /v1/auth/token`
Authenticate with a username and password to receive a JWT access token.
- **Request Body:** `{"username": "test", "password": "..."}`
- **Response:** `{"accessToken": "...", "expiresIn": 900}`

---

## AI Settings

### `GET /v1/settings/ai`
Retrieve the current AI provider configuration.

### `PUT /v1/settings/ai`
Update the AI provider settings (requires Admin privileges).
- **Request Body:**
```json
{
  "enabled": true,
  "provider": "openai",
  "model": "gpt-4",
  "baseURL": "https://api.openai.com",
  "apiKey": "sk-...",
  "defaultPromptMode": "REDACTED"
}
```

---

## Webhooks

Webhooks allow you to subscribe to events happening within CheckMate, such as when a scan completes or a finding is detected.

### `POST /v1/webhooks`
Register a new webhook.
- **Request Body:**
```json
{
  "url": "https://your-service.com/webhook",
  "events": ["scan.completed", "finding.detected"]
}
```
- **Response:** Returns the newly created webhook object, including the generated `secret` that will be used to sign outbound requests. **Note:** This is the *only* time the secret is returned via the API.

### `GET /v1/webhooks`
List all registered webhooks. Secrets are redacted.

### `DELETE /v1/webhooks/{webhookId}`
Delete a webhook.

### `POST /v1/webhooks/{webhookId}/test`
Triggers a test `ping` event to the specified webhook to verify connectivity and signature validation.

### Webhook Signatures
Outbound webhooks are signed using HMAC-SHA256. The signature is sent in the `X-CheckMate-Signature` header.
To verify:
1. Compute the HMAC-SHA256 hash of the raw HTTP request body using your webhook `secret`.
2. Compare the hex-encoded result with the value in the header.

---

## Triage, Context & Findings

### `GET /v1/projects/{projectId}/scans/{scanId}/findings`
Fetch the findings for a specific scan. Supports pagination.

### `GET /v1/findings/{findingId}/context`
Return numbered source code lines surrounding a finding from local disk or a retained remote checkout (falling back to stored `source_context`).
- **Query Parameters:** `scanId` (optional), `before` (default `20`), `after` (default `20`).

### `POST /v1/findings/{findingId}/triage`
Queue automated BYOK AI triage for a single finding.

### `PUT /v1/findings/{findingId}/triage`
Write back an external AI agent or human triage verdict (`true_positive`, `false_positive`, `needs_review`), optionally applying to all findings sharing `secretChecksum` and persisting a scoped exception.

### `POST /v1/scans/{scanId}/triage/batch`
Write back a batch of triage verdicts for a scan, update suppressions and `audit_log`, and recompute `scans.sanitised_summary`.

### `GET /v1/scans/{scanId}/sanitised`
Return the scan's sanitised summary together with active (non-suppressed) findings. Pass `?includeSuppressed=true` to include suppressed entries.

### `DELETE /v1/scans/{scanId}/checkout`
Delete any retained remote Git checkout associated with `scanId` (`keepCheckout: true`), clear its metadata in SQLite, and append an `audit_log` event.

---

## Streamable HTTP MCP Endpoint (`/v1/mcp`)

### `POST /v1/mcp`
Accepts a JSON-RPC 2.0 MCP request or batch (supports `initialize`, `tools/list`, `tools/call`, `resources/*`, `prompts/*`). Sets/honours the `Mcp-Session-Id` header.

### `GET /v1/mcp`
Opens an MCP Streamable HTTP Server-Sent Events (`Accept: text/event-stream`) stream for a session (`Mcp-Session-Id`), pushing server-initiated JSON-RPC notifications such as `notifications/progress` during scans.

### `DELETE /v1/mcp`
Closes the MCP HTTP session and tears down its SSE stream (`204 No Content`).

---

## Exceptions

- `GET /v1/exceptions` - List active exceptions (optional `?projectId=...`)
- `POST /v1/exceptions` - Create a scoped exception with justification and audit log entry
- `GET /v1/exceptions/{exceptionId}` - Fetch a single exception
- `PATCH /v1/exceptions/{exceptionId}` - Update justification, tags, or expiry
- `DELETE /v1/exceptions/{exceptionId}` - Revoke an exception
- `GET /v1/exceptions/export` / `POST /v1/exceptions/import` - Export or import `.checkmate.yaml`

