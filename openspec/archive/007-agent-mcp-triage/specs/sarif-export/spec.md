# Spec Delta: SARIF Export (`sarif-export`)

**Change:** 007-agent-mcp-triage

## Suppressions & Triage Metadata in SARIF 2.1.0

Resolves the deferred inline-suppression item in `openspec/specs/sarif-export/spec.md`.

### `GenerateSARIFWithOptions`

```go
type SARIFOptions struct {
    IncludeSuppressed bool
}

func GenerateSARIFWithOptions(writer io.Writer, findings []*store.StoredFinding, opts SARIFOptions) error
```

1. **Sanitised filtering (`IncludeSuppressed == false`):** Suppressed findings (`Suppressed == true` or `TriageStatus == "false_positive"`) are omitted from `runs[0].results`, leaving only actionable findings.
2. **Full audit SARIF (`IncludeSuppressed == true`):** Suppressed findings are included with standard SARIF 2.1.0 `suppressions`:
   ```json
   "suppressions": [
     {
       "kind": "external",
       "status": "accepted",
       "justification": "<triage summary / exception justification>"
     }
   ]
   ```
3. **Triage properties:** Findings with triage metadata include `properties.checkmateTriage` (`triageStatus`, `triageSource`, `summary`, `remediationHint`, `reasonCategory`).
4. **Schema conformance:** Output MUST validate cleanly against `pkg/report/testdata/sarif-schema-2.1.0.json`.
