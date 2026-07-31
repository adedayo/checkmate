# Spec: AI Triage

**Change:** 001-clean-slate-platform
**Status:** Draft

## Overview

CheckMate provides Bring-Your-Own-Key (BYOK) AI triage for detected secrets. Any OpenAI-compatible chat completions endpoint — cloud providers, self-hosted Ollama, vLLM, or any compatible API — can be used to annotate findings with false-positive likelihood, remediation hints, and contextual reasoning.

**Key invariant:** AI output NEVER overrides deterministic fields. `Finding.Severity` and `Finding.Confidence` remain pure functions of `SecretType` + detection confidence + verification status. `AIAnnotation` is a display-only overlay — it annotates, it does not score.

## Configuration

AI settings are stored in the `ai_settings` table (singleton row) with the following fields:

| Field | Type | Description |
|-------|------|-------------|
| `enabled` | BOOL | Master toggle for AI triage |
| `provider` | TEXT | Display name (e.g. `ollama`, `openai`, `azure`) |
| `model` | TEXT | Model identifier (e.g. `llama3`, `gpt-4o-mini`) |
| `base_url` | TEXT | Base URL of the chat completions endpoint |
| `api_key` | TEXT | API key (may be empty for local endpoints) |
| `default_prompt_mode` | TEXT | `REDACTED` (default) or `RAW_VALUE` |

### API

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/v1/settings/ai` | Retrieve current AI settings |
| `PUT` | `/v1/settings/ai` | Update AI settings |

## Prompt Modes

### REDACTED (default — always safe)

The raw secret value is replaced with `████` in the source context before sending to the AI provider. Variable names, file paths, and surrounding code are included. This is safe for any endpoint, including cloud providers.

### RAW_VALUE (local endpoints only)

When `CHECKMATE_AI_ALLOW_RAW_VALUE=true` **and** the configured `base_url` resolves to a private/loopback address, the raw secret value is included in the prompt alongside the source context.

**Security guardrail:** If the base URL resolves to a public/cloud address, the server silently downgrades to `REDACTED` mode regardless of the environment variable. This is enforced by `isLocalEndpoint(baseURL)` which checks for loopback (`127.0.0.1`, `::1`), RFC-1918 ranges (`10.x`, `172.16–31.x`, `192.168.x`), and plain Docker hostnames.

> **Note:** Raw secret values are never stored in the database. Even in `RAW_VALUE` mode, the value exists only in memory during the triage request.

## Triage Flow

### On-demand (per-finding)

```
POST /v1/findings/{findingId}/triage
```

1. Retrieve the finding from the database.
2. Load AI settings; return error if disabled.
3. Build the prompt using the configured prompt mode.
4. Send a chat completion request to the configured endpoint.
5. Parse the structured JSON response.
6. Store the resulting `AIAnnotation` on the finding.
7. Return the annotated finding.

### Chat Completions Request

The client uses the OpenAI-compatible `/chat/completions` API:

```json
{
  "model": "<configured model>",
  "messages": [
    { "role": "system", "content": "<system prompt>" },
    { "role": "user", "content": "<finding context>" }
  ],
  "response_format": { "type": "json_object" }
}
```

### Expected AI Response

```json
{
  "fpLikelihood": 0.0,
  "summary": "1-2 sentence assessment of the finding.",
  "remediationHint": "Brief suggestion on what to do next.",
  "contextClues": ["reasoning point 1", "reasoning point 2"]
}
```

- `fpLikelihood`: Float 0.0 (definitely real secret) to 1.0 (definitely false positive).
- `summary`: Plain-English assessment.
- `remediationHint`: Nullable remediation suggestion.
- `contextClues`: Array of strings explaining the model's reasoning.

## AIAnnotation Model

The `AIAnnotation` struct is stored as JSON in `findings.ai_annotation`:

| Field | Type | Description |
|-------|------|-------------|
| `model` | string | Model identifier used |
| `provider` | string | Provider name |
| `promptMode` | enum | `REDACTED` or `RAW_VALUE` |
| `fpLikelihood` | float | 0.0–1.0 false-positive probability |
| `summary` | string | Plain-English assessment |
| `remediationHint` | string | Remediation suggestion |
| `contextClues` | []string | Reasoning explanation |
| `generatedAt` | timestamp | When the annotation was created |
| `promptTokens` | int | Token count from the API response |
| `completionTokens` | int | Token count from the API response |

## Ollama Compose Profile

The `docker-compose.ollama.yml` profile provides a ready-to-use local AI endpoint:

```yaml
services:
  ollama:
    image: ollama/ollama
    volumes:
      - ollama-data:/root/.ollama
    ports:
      - "11434:11434"
```

This enables zero-configuration local triage with `base_url: http://ollama:11434/v1` inside Docker Compose.

## Additional Features

- **Batch triage:** Background job that triages all un-annotated findings in bulk. 
- **Cost tracking:** Token usage is recorded per annotation and aggregated into a usage endpoint.
