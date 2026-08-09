# CheckMate — Project Context

Hard-coded secrets in source code, configuration, logs, and history are the root cause of a large fraction of real-world breaches. CheckMate is a self-hosted, open-source secrets-detection platform that beats commercial SaaS offerings (GitGuardian, etc.) on every axis where they currently have an advantage — specifically: a delightful exception UX, real-time streaming, an LSP server for in-editor detection, BYOK AI triage, SARIF output for native CI integration, and a clean REST + WebSocket + SSE API with a Go library surface.

This file is read by AI coding agents working in this repo (OpenSpec convention) so they don't need to re-derive project conventions each session.

## Tech Stack

- **Language:** Go 1.24+
- **Database:** SQLite via `modernc.org/sqlite` (CGO-free, pure Go) with `golang-migrate/migrate/v4` for versioned schema migrations — replaced Badger KV store
- **HTTP/API:** `gorilla/mux` + `gorilla/handlers` + `gorilla/websocket` — migrating to `/v1/` route namespace
- **Detection engine:** `pkg/plugin/secrets-finder/` — in-repo (entropy + structural context + pattern matching), with `pkg/core` for shared types. Scans files in parallel behind a literal prefilter; see the `scan-engine` capability spec.
- **Git:** `go-git/go-git/v5` + `github.com/adedayo/git-service-driver`
- **Scheduler:** `robfig/cron/v3`
- **LSP:** `github.com/adedayo/go-lsp` (Language Server Protocol server for in-editor integration)
- **CLI:** `spf13/cobra` + `spf13/viper`
- **Report formats:** SARIF 2.1.0 (primary), CSV, HTML, PDF (native)
- **Container:** Single multi-mode image on `ghcr.io/adedayo/checkmate`; Docker Compose for self-hosted stack

## Non-Negotiable Guardrails

1. **AI output never overwrites deterministic fields.** `Finding.Severity` and `Finding.Confidence` are pure functions of `SecretType` + detection confidence + verification status. `AIAnnotation` is a separate display-only field — never a gate, never a scorer.
2. **Raw secret value never sent to cloud AI providers.** `CHECKMATE_AI_ALLOW_RAW_VALUE=true` is only honoured when `isLocalEndpoint(baseURL)` returns true (loopback, RFC-1918, or plain Docker hostname). Cloud endpoints silently fall back to REDACTED mode regardless of the flag.
3. **Secret values are never stored in plaintext.** Only `secretChecksum` (sha256) and `evidenceRedacted` (first 4 + last 4 chars) are persisted. The raw value exists only in memory during scanning.
4. **Stable finding identity.** `findingID = sha256(ruleID + repoURL + filePath + lineNumber + columnNumber + secretChecksum)` — same finding across different scans always has the same ID, enabling tracking without DB joins.
5. **Scan-engine performance work must be finding-identical.** Optimisations to the detection engine may not change the set of findings, and "may not" means a test rather than a review: the reference corpus is scanned with the prefilter on and off and at different worker counts, and the results must be byte-identical. Anything that *does* change detection or coverage — a length cap, a default directory prune — is a product decision, made explicitly and never as a side effect of a performance change.
6. **Scans are deterministic.** Files are scanned in parallel, so arrival order is nondeterministic by construction. Anything feeding a regex alternation, an iteration over a rule map, or overlap resolution must be explicitly ordered, and findings are sorted canonically before anything is derived from them.

## Conventions

- **Route namespace:** All new routes under `/v1/…`. The old `/api/…` routes are removed (clean break, no legacy compat).
- **OpenSpec:** Capability specs live under `openspec/changes/<id>/specs/<capability>/spec.md`. When a change is complete, specs merge into `openspec/specs/` and the change folder moves to `openspec/archive/`.
- **OpenAPI spec:** `openspec/specs/api-contract/openapi.yaml` is the single source of truth for the API. The spec is linted by Spectral in CI on every change.
- **SQLite store:** `pkg/store/sqlite/` implements `projects.ProjectManager`. Schema migrations live in `pkg/store/sqlite/migrations/` as versioned `.sql` files managed by `golang-migrate`.
- **SDK:** Public Go library surface is `pkg/sdk/` — importable by any Go program without spawning a subprocess or hitting HTTP.
- **Exception model:** Exceptions are first-class DB entities in the `exceptions` table, not raw YAML file entries. Export/import `.checkmate.yaml` is available but not the primary storage.
- **Auth:** Short-lived JWT (15 min) + refresh token (7 day) for human sessions. Scoped API keys (`cm_…` prefix, bcrypt-hashed, one-time display) for CI/headless. Dev mode (`CHECKMATE_DEV_MODE=true`) bypasses auth.
- **Streaming:** Every scan endpoint has both a WebSocket (`/stream`) and SSE (`/stream/sse`) variant. SSE is `text/event-stream`, no upgrade required — for restricted proxies and serverless environments.
- **SARIF:** CheckMate emits SARIF 2.1.0 with `partialFingerprints` from the stable `findingID`. The consuming workflow uploads to GitHub via `codeql-action/upload-sarif`. CheckMate does not hold GitHub API credentials.

## Spec-Driven Workflow

- `openspec/specs/` — accepted, current capability specs
- `openspec/changes/<id>/` — in-flight changes: `proposal.md`, `design.md`, `tasks.md`, `specs/<capability>/spec.md`
- On completing a change, archive it: merge spec deltas into `openspec/specs/` and move the change folder to `openspec/archive/`
- Accepted capabilities: `ai-triage`, `api-contract`, `authentication`, `data-store`, `exception-management`, `sarif-export`, `scan-engine`, `sdk`, `webhooks`
- Archived changes: `001-clean-slate-platform`, `003-scan-engine-performance`
- Current active changes:
  - `changes/002-app-modernisation/` — in progress
  - `changes/004-chunk-boundary-minimisation/` — scaffolded, not started. Reduces
    the offset-dependence exception accepted in 003 to a committed reproducing
    fixture. **Phase 1 is time-sensitive:** the only known reproducer lives in an
    uncommitted `node_modules` tree and does not survive `npm ci`.
  - `changes/005-sqlite-progress-reporting/` — scaffolded, not started.
    `sqlite.DB.RunScan` accepts `progressMonitor` and never calls it, so the
    WebSocket scan summary reports `fileCount: 0`. Pre-existing, verified at the
    pre-003 commit.
