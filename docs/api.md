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

## Triage & Findings

### `GET /v1/projects/{projectId}/scans/{scanId}/findings`
Fetch the findings for a specific scan. Supports pagination.

### `POST /v1/findings/{findingId}/triage`
Manually triage a finding (e.g. mark it as a false positive).
- **Request Body:** `{"status": "FALSE_POSITIVE", "reason": "Test credential"}`

### `POST /v1/projects/{projectId}/triage/batch`
Queue a batch of findings for automated AI triage analysis in the background.
- **Request Body:** `{"findingIds": ["f1", "f2"]}`
- **Response:** `{"status": "queued", "count": 2}`
