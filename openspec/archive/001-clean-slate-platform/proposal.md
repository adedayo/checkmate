# Change: 001-clean-slate-platform

## Why

CheckMate has strong detection capabilities — entropy analysis, structural context, pattern recognition, full git history scanning, LSP server integration, and a working project lifecycle. However, the API surface is implicit (no spec), exceptions require hand-edited YAML with no UX, the data store (Badger KV) makes relational queries painful, and the route namespace carries legacy design choices. This change rebuilds the platform surface as spec-first, with a clean API contract, a relational store, delightful exception management, BYOK AI triage, SARIF output, and a Go SDK — positioning CheckMate to exceed every commercial and open-source alternative.

## What Changes

- **API contract:** Full OpenAPI 3.1 spec, all routes migrated to `/v1/…`, SSE alongside every WebSocket endpoint
- **Authentication:** Dual-mode — short-lived JWT for human sessions + scoped API keys for CI/headless
- **Data store:** SQLite (`modernc.org/sqlite`, CGO-free) replaces Badger, with versioned schema migrations
- **Exception model:** First-class DB entities with expiry, drift detection, audit trail, and export/import
- **Finding taxonomy:** Structured `SecretType` enum replacing opaque rule-name strings
- **AI triage:** BYOK OpenAI-compatible layer (Ollama, cloud, any compatible endpoint); on-demand + background batch; raw-value opt-in for local endpoints only
- **SARIF output:** SARIF 2.1.0 with `partialFingerprints` for native GitHub Code Scanning
- **Go SDK:** `pkg/sdk` importable library surface
- **Webhooks:** Push notification on scan completion and new findings
- **CI:** Spectral spec linting + Go build + unit tests on every change

## Explicitly Out of Scope for This Change

- Live secret verification against issuing providers (deferred)
- Multi-user RBAC (deferred)
- VS Code extension (separate repo)
- Trawl integration wiring (separate change once SDK is stable)

## Rollout Phases

- **Phase 0 (current):** Foundation — OpenSpec structure, OpenAPI 3.1 spec, SQLite store, migrations, CI skeleton, SDK skeleton
- **Phase 1:** Clean API surface — all `/v1/` routes, JWT + API key auth, SSE endpoints, stable finding ID, SARIF output, SDK implementation
- **Phase 2:** Exception delight — first-class exception model, wizard API, expiry tracking, audit log, webhooks
- **Phase 3:** AI triage — BYOK config, on-demand + batch triage, Ollama Compose profile
- **Phase 4:** Trawl integration

See `tasks.md` for implementation checklist and `design.md` for technical approach.
