# Tasks: 001-clean-slate-platform

## Phase 0 — Foundation

- [x] Create OpenSpec directory structure
- [x] Write project.md context file
- [x] Write proposal.md
- [x] Create OpenAPI 3.1 spec (`openapi.yaml`)
- [x] Implement SQLite store (`pkg/store/sqlite/`)
- [x] Create initial schema migration (`001_initial_schema.up.sql`)
- [x] Implement `PlatformStore` interface (`pkg/store/store.go`)
- [x] Set up Spectral linting config (`.spectral.yaml`)
- [x] Create SDK skeleton (`pkg/sdk/`)
- [x] Write capability specs:
  - [x] `authentication/spec.md`
  - [x] `data-store/spec.md`
  - [x] `exception-management/spec.md`
  - [x] `ai-triage/spec.md`
  - [x] `sarif-export/spec.md`
  - [x] `sdk/spec.md`
  - [x] `webhooks/spec.md`
- [x] Write `design.md`
- [x] Write `tasks.md`

## Phase 1 — Clean API Surface

- [x] Implement `/v1/auth/login` (JWT token issuance)
- [x] Implement `/v1/auth/refresh` (token refresh)
- [x] Implement `/v1/auth/logout` (revoke refresh token)
- [x] Create refresh tokens migration (`002_auth_refresh_tokens.up.sql`)
- [x] Implement API key creation (`POST /v1/auth/keys`)
- [x] Implement API key listing (`GET /v1/auth/keys`)
- [x] Implement API key revocation (`DELETE /v1/auth/keys/{keyID}`)
- [x] Implement `/v1/system/health` and `/v1/system/ready`
- [x] Implement `/v1/findings/search` (paginated finding search)
- [x] Implement `/v1/projects/{projectId}/scans` (list + start)
- [x] Implement SSE endpoint (`/v1/projects/{projectId}/scans/{scanId}/events`)
- [x] Implement `ScanEventBroker` pub/sub (`pkg/store/pubsub.go`)
- [x] Implement stable finding ID computation in SDK
- [x] Implement `SecretType` taxonomy enum and classifier
- [x] Implement SARIF 2.1.0 generator (`pkg/report/sarif.go`)
- [x] Wire SARIF export to an API endpoint or CLI command
- [x] Add auth middleware to `/v1/` routes (currently dev-mode bypass)
- [x] Implement `isLocalEndpoint(baseURL)` guardrail for raw value AI mode
- [x] CI pipeline: Spectral lint + `go build` + `go test` on every PR

## Phase 2 — Exception Delight

- [x] Implement exception CRUD (`pkg/store/sqlite/exceptions.go`)
- [x] Implement exception API handlers (`pkg/api/exceptions.go`)
- [x] Implement audit log persistence (`insertAuditLogTx`, `getAuditLogsTx`)
- [x] Implement exception export (`GET /v1/exceptions/export`)
- [x] Implement exception import (`POST /v1/exceptions/import`)
- [x] Implement exception validate (`POST /v1/exceptions/validate`)
- [x] Wire exception matching into scan pipeline (auto-suppress matched findings)
- [x] Implement exception expiry checking (background or on-read)
- [ ] Implement drift detection (compare evidence hash to current file state) - DEFERRED

## Phase 3 — AI Triage

- [x] Implement AI triage client (`pkg/ai/client.go`)
- [x] Implement prompt templates (`pkg/ai/prompts.go`)
- [x] Implement AI settings storage (`003_ai_settings.up.sql`)
- [x] Implement `GET/PUT /v1/settings/ai`
- [x] Implement `POST /v1/findings/{findingId}/triage`
- [x] Create Ollama Docker Compose profile (`docker-compose.ollama.yml`)
- [x] Implement batch triage (background job for un-annotated findings)
- [x] Implement `isLocalEndpoint` URL validation for RAW_VALUE mode
- [x] Add token usage aggregation / cost tracking

## Phase 4 — Webhooks & Integration

- [x] Implement webhook CRUD (`pkg/store/sqlite/webhooks.go`)
- [x] Implement webhook API handlers (`pkg/api/webhooks.go`)
- [x] Implement webhook secret generation (crypto/rand, 32 bytes)
- [x] Implement test webhook endpoint (`POST /v1/webhooks/{webhookId}/test`)
- [x] Implement actual webhook delivery (HTTP POST with HMAC signature)
- [x] Implement delivery retry with exponential backoff
- [x] Implement delivery logging (attempt, response code, latency)

## Cross-Cutting

- [ ] Add comprehensive unit tests for SDK
- [ ] Add integration tests for `/v1/` API surface
- [ ] Add SARIF output validation against OASIS schema
- [ ] Document API in README or dedicated docs
- [ ] Archive change: merge specs into `openspec/specs/` and move to `openspec/archive/`
