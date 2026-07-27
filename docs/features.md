# CheckMate Features & Capabilities

CheckMate is a fast, accurate, and developer-friendly secrets detection and posture management platform. Below is a comprehensive list of its key features along with quick snippets of how to use them.

---

## 1. Webhook Notifications

**What they enable:** 
Webhooks allow CheckMate to push real-time event notifications directly to external systems (e.g., Slack, Jira, PagerDuty, or custom CI/CD pipelines). Instead of polling the API to check if a scan is finished or if new secrets were found, your external systems can simply listen for HTTP POST payloads from CheckMate.

**Usage Documentation:**
You can register a webhook that listens to specific events (like `scan.completed` or `finding.detected`).

```bash
curl -X POST http://localhost:8080/v1/webhooks \
  -H "Authorization: Bearer <JWT_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://hooks.slack.com/services/T0000/B000/XXXX",
    "events": ["scan.completed", "finding.detected"],
    "description": "Notify Slack security channel"
  }'
```
*Note: CheckMate will return a one-time `secret` in the response for you to verify the HMAC signature of incoming payloads.*

---

## 2. Bring-Your-Own-Key (BYOK) AI Triage

**Capabilities:**
Instead of relying on human analysts to triage every single potential false positive, CheckMate integrates natively with OpenAI-compatible endpoints. You can hook it up to a local Ollama instance (e.g. `llama3` or `mistral`) or cloud LLMs. The AI analyzes the surrounding code context and provides a `fpLikelihood` (false positive probability) and a brief summary.

**Usage Documentation:**
Configure your AI endpoint via the settings API:

```bash
# Configure for a local Ollama instance
curl -X PUT http://localhost:8080/v1/settings/ai \
  -H "Authorization: Bearer <JWT_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "enabled": true,
    "provider": "ollama",
    "model": "llama3",
    "baseUrl": "http://localhost:11434/v1",
    "defaultPromptMode": "REDACTED"
  }'
```

Request an async AI Triage on a specific finding:
```bash
curl -X POST http://localhost:8080/v1/findings/<FINDING_ID>/triage \
  -H "Authorization: Bearer <JWT_TOKEN>"
```
*This responds with `202 Accepted`. Check the finding later to see the attached `aiAnnotation`.*

---

## 3. Advanced Exception Management

**Capabilities:**
CheckMate exceptions are not just simple ignore-lists. They are first-class entities with scopes (global, project, directory, file, exact line, or exact secret value), mandatory justifications, expiration dates, and immutable audit logs to track who created or revoked an exception.

**Usage Documentation:**
Creating a time-bound exception for a specific file:

```bash
curl -X POST http://localhost:8080/v1/exceptions \
  -H "Authorization: Bearer <JWT_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "ruleId": "HIGH_ENTROPY_STRING",
    "scope": {
      "type": "file",
      "path": "tests/dummy_data.go"
    },
    "reason": "Test fixture data",
    "expiresAt": "2026-12-31T23:59:59Z"
  }'
```

---

## 4. SARIF Output Support

**Capabilities:**
CheckMate can output scan results natively in SARIF 2.1.0 (Static Analysis Results Interchange Format), which includes `partialFingerprints`. This allows seamless integration into GitHub Code Scanning and other enterprise SIEM dashboards without any middleware converters.

**Usage Documentation:**
When triggering a CLI scan, you can specify SARIF format:

```bash
checkmate search --sarif <path_to_repository> > results.sarif
```
Or via the API when pulling scan results, depending on the route content negotiation.

---

## 5. Local CLI Scanning & IDE Integration

**Capabilities:**
While CheckMate shines as a platform, the core engine runs incredibly fast on local filesystems and git repositories without uploading code to the cloud.

**Usage Documentation:**
Scan a local GitHub clone directly:
```bash
go run checkmate.go search https://github.com/example/repo
```
