# Spec: Go SDK

**Change:** 001-clean-slate-platform
**Status:** Draft

## Overview

The CheckMate Go SDK (`pkg/sdk`) provides an importable library surface for running secret scans from any Go program — without spawning a subprocess, hitting HTTP, or depending on the CheckMate server. It wraps the core detection engine with a clean, stable public API.

**Import path:** `github.com/adedayo/checkmate/pkg/sdk`

## Design Principles

1. **Zero infrastructure dependency.** The SDK embeds the detection engine directly. No server, no database, no network required.
2. **Stable finding identity.** Every finding gets a deterministic `ID = sha256(ruleID + repoURL + filePath + lineNumber + columnNumber + secretChecksum)`. Same physical secret always produces the same ID.
3. **No raw secret storage.** The `Finding` struct never contains the raw secret value. Only `SecretChecksum` (sha256) and `EvidenceRedacted` (first 4 + last 4 chars) are available.
4. **Structured taxonomy.** Opaque rule-name strings are mapped to the `SecretType` enum for programmatic consumption.

## Core Types

### Scanner

```go
type Scanner struct { ... }

func NewScanner(opts Options) *Scanner
```

Create once, reuse across scans. Holds no per-scan state.

### Options

```go
type Options struct {
    ShowSource         bool     // Include surrounding source context in findings
    CalculateChecksum  bool     // Compute sha256 of detected secrets
    ExcludeTestFiles   bool     // Skip test files during scanning
    SensitiveFilesOnly bool     // Only scan known sensitive file types
    ExclusionFile      string   // Path to a .checkmate.yaml exception policy
    ExcludePatterns    []string // Glob patterns to exclude
}

func DefaultOptions() Options  // ShowSource: true, CalculateChecksum: true
```

### Finding

```go
type Finding struct {
    ID                 string             // Stable deterministic sha256
    RuleID             string             // Detection rule name
    SecretType         SecretType         // Structured taxonomy enum
    Severity           Severity           // CRITICAL|HIGH|MEDIUM|LOW|INFO
    Confidence         Confidence         // CONFIRMED|HIGH|MEDIUM|LOW
    RepositoryURL      string             // Empty for filesystem scans
    CommitSHA          string             // Empty for filesystem scans
    Branch             string
    File               string
    Line               int                // 1-indexed
    Column             int                // 1-indexed
    EvidenceRedacted   string             // First 4 + last 4 chars
    SecretChecksum     string             // sha256 of raw value
    SourceContext      string             // Surrounding code with ████
    Suppressed         bool
    ExceptionID        string
    VerificationStatus VerificationStatus // Always NOT_CHECKED (deferred)
    VerifiedAt         *time.Time
    AIAnnotation       *AIAnnotation      // nil until triage is run
    DetectedAt         time.Time
}
```

### SecretType Taxonomy

| Category | Values |
|----------|--------|
| Cloud | `aws.access_key`, `aws.secret_key`, `aws.session_token`, `gcp.service_account_key`, `azure.client_secret`, `azure.sas_token` |
| Source Control | `github.personal_access_token`, `github.fine_grained_token`, `github.app_private_key`, `gitlab.personal_access_token` |
| Database | `db.password`, `db.connection_string` |
| Cryptographic | `crypto.rsa_private_key`, `crypto.ec_private_key`, `crypto.pkcs12`, `crypto.pem_private_key`, `crypto.ssh_private_key` |
| Generic | `generic.high_entropy`, `generic.password`, `generic.api_key`, `generic.token`, `generic.jwt` |

### Severity & Confidence

- **Severity:** `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`
- **Confidence:** `CONFIRMED`, `HIGH`, `MEDIUM`, `LOW`
- **Invariant:** These are pure functions of the detection result. AI triage never modifies them.

### VerificationStatus

`NOT_CHECKED` (default), `ACTIVE`, `REVOKED`, `UNKNOWN`. Live verification is a deferred feature.

## Scanning Methods

### ScanPath (blocking)

```go
func (s *Scanner) ScanPath(ctx context.Context, paths ...string) ([]Finding, error)
```

Scans one or more local filesystem paths or git repository URLs. Blocks until the scan completes and returns all findings.

### ScanGitRepo (convenience)

```go
func (s *Scanner) ScanGitRepo(ctx context.Context, repoURL string) ([]Finding, error)
```

Equivalent to `ScanPath` with a single git URL.

### ScanStream (streaming)

```go
func (s *Scanner) ScanStream(ctx context.Context, paths ...string) <-chan Finding
```

Streams findings as they are detected. The returned channel is closed when the scan completes. Supports context cancellation.

### ScanStreamWithProgress (streaming + progress)

```go
func (s *Scanner) ScanStreamWithProgress(ctx context.Context, paths ...string) (<-chan Finding, <-chan ScanProgress)
```

Returns two channels: findings and progress updates. Both are closed on completion.

```go
type ScanProgress struct {
    CurrentFile  string
    FilesScanned int
    TotalFiles   int  // May be 0 if not known in advance
}
```

## Usage Example

```go
package main

import (
    "context"
    "fmt"
    "github.com/adedayo/checkmate/pkg/sdk"
)

func main() {
    scanner := sdk.NewScanner(sdk.DefaultOptions())
    findings, err := scanner.ScanPath(context.Background(), "./src")
    if err != nil {
        panic(err)
    }
    for _, f := range findings {
        fmt.Printf("[%s] %s:%d — %s\n", f.Severity, f.File, f.Line, f.SecretType)
    }
}
```

## Exclusion Support

When `Options.ExclusionFile` is set, the SDK reads a `.checkmate.yaml` file containing exclusion definitions (path globs, rule overrides, etc.) and merges them with the built-in common exclusions. Invalid exclusion files produce a log warning but do not abort the scan.

## Deferred

- **SDK tests:** Unit and integration tests for the SDK surface.
- **ScanProgress for filesystem scans:** The underlying plugin currently does not emit granular progress during filesystem scans.
- **EvidenceRedacted population:** Redacted evidence is not yet computed from the source context.
