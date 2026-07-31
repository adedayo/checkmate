# Design: 001-clean-slate-platform

## Architecture Overview

The clean-slate platform rebuilds CheckMate's infrastructure layer while preserving the proven detection engine (`secrets-finder` plugin). The architecture is a single-binary, multi-mode Go application backed by an embedded SQLite database.

```
┌─────────────────────────────────────────────────────┐
│                   CheckMate Binary                  │
│                                                     │
│  ┌───────────┐  ┌───────────┐  ┌────────────────┐  │
│  │  CLI      │  │  API      │  │  LSP Server    │  │
│  │  (cobra)  │  │  (gorilla)│  │  (go-lsp)      │  │
│  └─────┬─────┘  └─────┬─────┘  └───────┬────────┘  │
│        │              │                 │           │
│  ┌─────▼──────────────▼─────────────────▼────────┐  │
│  │              PlatformStore Interface           │  │
│  │  (projects.ProjectManager + auth.Store +      │  │
│  │   exceptions + webhooks + AI settings)         │  │
│  └───────────────────┬───────────────────────────┘  │
│                      │                              │
│  ┌───────────────────▼───────────────────────────┐  │
│  │            SQLite (modernc.org/sqlite)         │  │
│  │  WAL mode · single-writer · embedded          │  │
│  └───────────────────────────────────────────────┘  │
│                                                     │
│  ┌───────────────────────────────────────────────┐  │
│  │         Detection Engine (secrets-finder)      │  │
│  │  Entropy + structural context + patterns       │  │
│  └───────────────────────────────────────────────┘  │
│                                                     │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────┐  │
│  │  SDK     │  │  SARIF   │  │  AI Triage       │  │
│  │ (pkg/sdk)│  │ (pkg/    │  │  (pkg/ai)        │  │
│  │          │  │  report) │  │                   │  │
│  └──────────┘  └──────────┘  └──────────────────┘  │
└─────────────────────────────────────────────────────┘
```

## Storage Layer

### PlatformStore Interface

`pkg/store/store.go` defines the `PlatformStore` interface — a composition of:

- `projects.ProjectManager` — existing project/scan lifecycle (preserved from the original codebase)
- `auth.Store` — JWT refresh tokens and API key management
- Platform-specific methods: finding search, exceptions CRUD, webhooks CRUD, AI settings

This interface decouples the API layer from the storage backend. The only implementation is `pkg/store/sqlite/`.

### SQLite Implementation

- **Driver:** `modernc.org/sqlite` — pure Go, no CGO, single static binary.
- **Mode:** WAL (Write-Ahead Logging) for concurrent read performance.
- **Connection pool:** `MaxOpenConns(1)`, `MaxIdleConns(1)` — single-writer avoids `SQLITE_BUSY`.
- **Migrations:** `golang-migrate/migrate/v4` with embedded SQL files via `embed.FS`.
- **PRAGMAs:** `journal_mode=WAL`, `foreign_keys=ON`, `busy_timeout=5000`.

### Schema Design

The schema is intentionally denormalised in places to avoid expensive joins on hot read paths:

- `findings` stores `project_id` directly (no join through `scans`).
- `projects.data` stores the full project struct as serialised JSON.
- Complex nested objects (`scope_json`, `evidence_json`, `tags`) use JSON columns.

Composite primary key `(finding_id, scan_id)` on `findings` allows the same finding to appear in multiple scans while maintaining stable identity.

## API Surface

### Route Namespace

All new routes live under `/v1/`. The old `/api/` routes are preserved for backward compatibility with the existing UI but are not part of the new spec.

### Dual Streaming

Every scan endpoint supports both:

- **WebSocket** (`/api/secrets/scan`, `/api/monitor/projectscan`) — for the existing UI
- **SSE** (`/v1/projects/{projectId}/scans/{scanId}/events`) — for restricted proxies, serverless environments, and the new API surface

SSE uses `text/event-stream` with named events (`finding`, `progress`, `complete`) and 15-second keepalive pings.

### Event Broker

`pkg/store/pubsub.go` provides a `ScanEventBroker` — an in-memory pub/sub system for streaming scan events to SSE clients. Each scan gets a topic. Subscribers receive events through a Go channel and are cleaned up on disconnect.

## Authentication

### Dual-Mode

1. **JWT Bearer tokens** — short-lived (15 min) access + 7-day refresh. Signed with `CHECKMATE_JWT_SECRET` (HS256).
2. **Scoped API keys** — `cm_` prefixed, bcrypt-hashed, one-time display. Scopes: `scan:read`, `scan:write`, `exception:read`, `exception:write`, `admin`.

Both use `Authorization: Bearer <token>`. The server distinguishes by prefix (`cm_` = API key).

### Dev Mode

When `CHECKMATE_DEV_MODE=true` (or `--bind` resolves to localhost), authentication is bypassed.

## Detection & Finding Identity

The detection engine is untouched — `secrets-finder` provides entropy analysis, structural context, and pattern matching.

Finding identity is deterministic:

```
finding_id = sha256(rule_id + repo_url + file_path + line_number + column_number + secret_checksum)
```

This ensures the same physical secret always has the same ID across scans.

## Security Guardrails

1. **Secret values never stored.** Only `secret_checksum` (sha256) and `evidence_redacted` (first 4 + last 4 chars). Raw value exists only in memory during scanning.
2. **AI never modifies deterministic fields.** `Severity` and `Confidence` are pure functions. `AIAnnotation` is display-only.
3. **Raw value never sent to cloud AI.** `CHECKMATE_AI_ALLOW_RAW_VALUE=true` is enforced only for loopback/RFC-1918/Docker endpoints. Cloud endpoints silently fall back to `REDACTED`.
4. **API keys never stored in plaintext.** Only bcrypt hash + 8-char display prefix.

## Container Strategy

Single multi-mode image on `ghcr.io/adedayo/checkmate`. Docker Compose profiles:

- **Default:** CheckMate API server with SQLite volume
- **Ollama profile** (`docker-compose.ollama.yml`): Adds Ollama sidecar with auto-pull of `llama3` for local AI triage
