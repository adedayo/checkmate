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

## 2. Bring-Your-Own-Key (BYOK) AI Triage & Auto-Suppression Engine

**Capabilities:**
Instead of relying on human analysts to manually review every potential finding, CheckMate integrates natively with **any OpenAI-compatible or Anthropic endpoint**, as well as local air-gapped models via [Ollama](https://ollama.com/), DeepSeek, and custom LLM providers. 

The AI engine analyzes code context, structural evidence, and entropy to evaluate findings:
- **`fpLikelihood` Score:** False positive probability rating (0% to 100%).
- **Plain-Language Summary & Remediation Hints:** Detailed analysis explaining why a secret is genuine or a false positive (e.g. test mock, public hash, placeholder).
- **Automated Auto-Suppression:** When `autoTriage` is enabled, findings exceeding your configured confidence threshold (e.g., `fpLikelihood >= 80%`) are automatically suppressed with auto-generated exception records.
- **Privacy & Token Control:** Choose between `REDACTED` (masks sensitive values before sending) and `FULL` context modes. When paired with local models (Ollama), **zero code or tokens leave your network**.
- **Human-in-the-Loop & Decision Memory:** If an analyst deletes an AI suppression or clicks **"Mark as True Positive"**, CheckMate sets `UserOverridden = true`. CheckMate's persistent database remembers user overrides across scans, ensuring **the AI engine never re-suppresses a user-confirmed finding on subsequent scans**.

**Usage Documentation:**
Configure your AI endpoint via the settings API:

```bash
# Configure for a local Ollama instance with Auto-Suppression at 80% threshold
curl -X PUT http://localhost:8080/v1/settings/ai \
  -H "Authorization: Bearer <JWT_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "enabled": true,
    "provider": "ollama",
    "model": "llama3",
    "baseUrl": "http://localhost:11434/v1",
    "confidenceThreshold": 0.8,
    "defaultPromptMode": "REDACTED",
    "autoTriage": true
  }'
```

Request an async AI Triage on a specific finding:
```bash
curl -X POST http://localhost:8080/v1/findings/<FINDING_ID>/triage \
  -H "Authorization: Bearer <JWT_TOKEN>"
```

Trigger Bulk AI Triage across all un-triaged findings in a project:
```bash
curl -X POST http://localhost:8080/v1/projects/<PROJECT_ID>/ai-triage \
  -H "Authorization: Bearer <JWT_TOKEN>"
```
*Responds with `202 Accepted`. Findings are triaged asynchronously in the background. High-confidence false positives are auto-suppressed.*

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

---

## 6. Scan Engine Performance & Tuning

**Capabilities:**
Files are scanned in parallel by a worker pool, each rule set is gated behind a
literal prefilter so that only rules that could possibly match are run, and
progress is coalesced onto a fixed interval rather than emitted per file.

Two properties are worth stating explicitly, because they are what make the
tuning knobs below safe to touch:

- **Results do not depend on tuning.** The worker count, the prefilter and the
  progress interval are all performance controls. None of them changes the set
  of findings. This is enforced by tests that scan a reference corpus with the
  prefilter on and off, and at different worker counts, and require the results
  to be byte-identical.
- **Results do not depend on timing.** Findings are sorted into a canonical
  order before anything is derived from them, so two scans of the same tree
  produce the same output in the same order, regardless of which worker
  finished first.

### Tuning environment variables

All of these are optional. The defaults are intended to be correct for most
users, and every one of them is ignored (rather than fatal) if it is set to
something unparseable — a mistyped tuning knob should not fail a scan.

| Variable | Default | Effect |
| --- | --- | --- |
| `CHECKMATE_SCAN_WORKERS` | `GOMAXPROCS` | Number of files scanned concurrently. Set to `1` for strictly sequential scanning. Useful for capping CheckMate's footprint on a shared CI runner. |
| `CHECKMATE_PROGRESS_INTERVAL` | `250ms` | How often progress is reported. Accepts a Go duration (`500ms`, `2s`) or a bare number read as milliseconds. |
| `CHECKMATE_CLONE_CONCURRENCY` | `4` | How many repositories are cloned at once. Deliberately modest: the other side is somebody else's Git server. |
| `CHECKMATE_DISABLE_PREFILTER` | unset | Set to `1` to run every rule against every file. Should not change results — it exists as an escape hatch and as the control arm of the equivalence test. |
| `CHECKMATE_PRUNE_DIRS` | unset (no pruning) | Comma-separated directory names to skip. **Replaces** the built-in suggestion list rather than adding to it; setting it empty disables pruning. |

The same controls are available programmatically on `SecretSearchOptions`
(`Workers`, `ProgressInterval`, `CloneConcurrency`, `DisablePrefilter`), which
take precedence over the environment.

### A note on `CHECKMATE_PRUNE_DIRS`

Directory pruning is **off by default, and that is deliberate.** Skipping
`node_modules`, `vendor`, `dist`, `.git` and friends is worth roughly 2× on a
dependency-heavy tree, so it is tempting to make it the default — but those
directories are not excluded today, which means they are scanned today, and
they contain real secrets: an `.npmrc` auth token under `node_modules`, an API
key baked into `dist/bundle.js`, a `https://user:token@host` remote in
`.git/config`.

Turning it on is therefore a speed-for-coverage trade, and it is one the
operator makes explicitly:

```bash
# Roughly 2x faster on a dependency-heavy tree, at the cost of not scanning these
CHECKMATE_PRUNE_DIRS='node_modules,vendor,dist,.git' checkmate search ./my-project
```

### Large and adversarial inputs

Very large single-line files — minified bundles, serialised blobs, base64
assets — are the worst case for any regex-based scanner, and they are
attacker-influenced wherever someone can commit a file. CheckMate bounds this
in two ways: files above a size cut-off are hashed and skipped rather than
scanned, and the rules that survive the prefilter on such content are the
generic ones doing genuine detection work.

Multi-megabyte single-line files remain the slowest thing the engine does. If a
scan is slow, that is the first place to look — run with `--verbose` to see the
file being scanned.
