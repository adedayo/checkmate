# Spec Delta: AI Triage (`ai-triage`)

**Change:** 007-agent-mcp-triage

## External Agent Triage Write-Back

In addition to CheckMate's built-in BYOK `/chat/completions` triage loop, external AI agents (via MCP or REST) may submit structured triage verdicts for findings after investigating them in repository context.

### Extended `AIAnnotation` Fields

| Field | Type | Description |
|-------|------|-------------|
| `verdict` | string | `true_positive`, `false_positive`, or `needs_review` |
| `reasonCategory` | string | Structured FP/TP category (e.g. `test_fixture`, `example_placeholder`, `non_secret_identifier`, `config_key_name`, `real_credential`) |
| `triageSource` | string | Identifier of the agent or model that performed triage |

### Invariant Preservation

- Deterministic `Finding.Severity` and `Finding.Confidence` are NEVER overwritten by agent verdicts.
- False-positive suppression operates exclusively through `findings.suppressed`, `findings.exception_id`, `findings.triage_status`, and the `exceptions` table.
- Every agent triage mutation is recorded in `audit_log`.
