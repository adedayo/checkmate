# Spec: SARIF Export

**Change:** 001-clean-slate-platform
**Status:** Draft

## Overview

CheckMate emits SARIF 2.1.0 (Static Analysis Results Interchange Format) output for native integration with GitHub Code Scanning, Azure DevOps, and any SARIF-consuming tool. The SARIF output uses `partialFingerprints` derived from CheckMate's stable `finding_id` to enable cross-scan deduplication in the consuming platform.

## SARIF Version

**SARIF 2.1.0** — conformant with the OASIS specification.

- Schema: `https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json`
- Version field: `"2.1.0"`

## Document Structure

```json
{
  "version": "2.1.0",
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "CheckMate",
          "informationUri": "https://github.com/adedayo/checkmate",
          "rules": [ ... ]
        }
      },
      "results": [ ... ]
    }
  ]
}
```

## Tool Driver

- **name:** `CheckMate`
- **informationUri:** `https://github.com/adedayo/checkmate`
- **rules:** Deduplicated array of rules observed in the scan. Each rule has:
  - `id`: The rule ID (e.g. `aws.access_key`, `generic.high_entropy`)
  - `shortDescription.text`: Human-readable description
  - `defaultConfiguration.level`: Default SARIF level for this rule

## Rules

Rules are collected from the scan results. Each unique `ruleId` produces one entry in `tool.driver.rules`. The `id` maps to CheckMate's `SecretType` taxonomy or the detection rule name.

## Results

Each finding produces one result entry:

| SARIF Field | Source |
|-------------|--------|
| `ruleId` | `Justification.Headline.Description` (rule name) |
| `level` | Mapped from CheckMate confidence: `HIGH+` → `error`, `MEDIUM` → `warning`, `LOW/INFO` → `note` |
| `message.text` | `"Detected secret of type: <ruleId>"` |
| `locations[0].physicalLocation.artifactLocation.uri` | Finding file path |
| `locations[0].physicalLocation.region.startLine` | 1-indexed line number |
| `locations[0].physicalLocation.region.startColumn` | 1-indexed column number |
| `partialFingerprints["checkmate/v1"]` | SHA-256 checksum of the detected secret |

## Severity / Level Mapping

| CheckMate Confidence | SARIF Level |
|----------------------|-------------|
| `HIGH`, `CONFIRMED` | `error` |
| `MEDIUM` | `warning` |
| `LOW`, `INFO` | `note` |

## Partial Fingerprints

```json
"partialFingerprints": {
  "checkmate/v1": "<sha256 of the secret value>"
}
```

The `checkmate/v1` fingerprint key uses the secret's SHA-256 checksum (`findings.secret_checksum`). This enables the consuming platform (e.g. GitHub Code Scanning) to deduplicate the same secret across different SARIF uploads, even if the file path or line number changes.

## Implementation

The SARIF generator lives in `pkg/report/sarif.go` and exposes:

```go
func GenerateSARIF(writer io.Writer, diags []*diagnostics.SecurityDiagnostic) error
```

It takes the raw scan diagnostics and writes a complete SARIF 2.1.0 JSON document to the provided writer.

## GitHub Code Scanning Integration

The intended consumption workflow:

1. CheckMate runs as a CI step and writes SARIF to a file.
2. The GitHub Actions workflow uploads SARIF via `github/codeql-action/upload-sarif@v3`.
3. GitHub Code Scanning ingests the SARIF and displays findings as code scanning alerts.

**CheckMate does not hold GitHub API credentials.** The upload is handled entirely by the CI workflow.

Example GitHub Actions step:

```yaml
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: checkmate-results.sarif
```

## Deferred

- **Inline suppression annotations:** Mapping CheckMate exceptions to SARIF `suppressions[]` entries. Will be added once the exception-to-finding matching is fully wired.
- **EndLine / EndColumn:** Currently only `startLine` and `startColumn` are populated. `endLine` and `endColumn` fields exist in the schema but are not yet set.
