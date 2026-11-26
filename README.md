<p align="center">
  <img src="logo-horizontal.svg" alt="CheckMate Logo" width="600">
</p>

# CheckMate: Hard-coded Secrets Detection

[![golangci-lint](https://github.com/adedayo/checkmate/actions/workflows/golangci-lint.yml/badge.svg)](https://github.com/adedayo/checkmate/actions/workflows/golangci-lint.yml)
![GitHub release](https://img.shields.io/github/release/adedayo/checkmate.svg)
[![GitHub license](https://img.shields.io/github/license/adedayo/checkmate.svg)](https://github.com/adedayo/checkmate/blob/master/LICENSE)
[![Docs & Overview](https://img.shields.io/badge/docs-GitHub%20Pages-10b981.svg)](https://adedayo.github.io/checkmate/)

![CheckMate Reporting](checkmate-report.png)

---

## Why CheckMate? A Security Leader's Perspective

Hard-coded secrets (API keys, passwords, tokens, and certificates embedded in source code) are one of the most persistent and underestimated risks in software development. A single leaked credential can be the difference between a routine day and a breach that makes the news.

**Why this deserves a place in your security strategy:**

- **The exploitation window is minutes, not days.** Automated scanners continuously sweep public repositories for credentials. Research shows secrets pushed to GitHub are typically found within minutes. The question is not whether a leaked secret gets discovered; it is whether an attacker finds it before you do.
- **You cannot fix what you cannot see.** Most engineering organisations genuinely do not know how many hard-coded secrets exist across their codebases, CI/CD configurations, Dockerfiles, and log outputs. Without systematic detection, you are managing a risk you cannot quantify.
- **Secrets sprawl far beyond source code.** API keys and passwords turn up in configuration files, pipeline logs, `.env` files, application startup output, and test fixtures, across every repository and every team. A single audit is a snapshot; CheckMate provides continuous visibility.
- **Compliance frameworks require demonstrable controls.** PCI-DSS, SOC 2, ISO 27001, and GDPR require active, evidenced controls over credential management. Exception justifications, scan history, and immutable audit trails are the kind of artefacts that pass an audit, not policies alone.
- **False positives destroy adoption.** Security tooling that cries wolf gets disabled. CheckMate's AI triage layer reduces analyst noise, ensuring the findings that surface are worth acting on.

---

## What CheckMate Does

CheckMate uses a multi-layered detection engine combining **entropy analysis**, **structural context**, and **pattern recognition** to find hard-coded secrets in:

- Source code (Java, C/C++, C#, Ruby, Scala, Go, and more)
- Configuration files (YAML, XML, `.env`, properties files)
- Log files and application output
- Sensitive file types (certificates, key stores, private keys)
- Git repositories, including remote repositories scanned directly by URL

Detection results include:
- The exact location (file, line, column) of the finding
- Checksums of the detected secret value for safe deduplication and tracking
- A severity rating and secret type classification
- Source code context as evidence

---

## Key Platform Capabilities

### 🔐 Bring-Your-Own-Key (BYOK) AI Triage

Alert fatigue is the enemy of effective security. CheckMate integrates with **any OpenAI-compatible endpoint** (including local, air-gapped models via [Ollama](https://ollama.com/)) to automatically assess whether a finding is a genuine secret or a false positive. Each AI-triaged finding gets a `fpLikelihood` score, a plain-language summary, remediation hints, and a full token usage audit trail. Critically, **your code never leaves your infrastructure**: you control the AI, and you hold the keys.

### 🛡️ Auditable Exception Management

Not every flagged value is actionable immediately. CheckMate exceptions are **first-class governed entities**, not a simple ignore list. Each exception requires:

- A mandatory justification and reason
- A defined scope (global, project, directory, file, exact line, or secret checksum)
- An optional expiry date (exceptions auto-expire; risk doesn't just disappear)
- A full, immutable audit trail of who created, modified, or revoked the exception

This gives security and compliance teams a defensible, auditable record of every suppression decision.

### 📡 Real-Time Webhook Notifications

CheckMate can push `scan.completed` and `finding.detected` events to any external HTTP endpoint: Slack, Jira, PagerDuty, SIEM platforms, or custom CI/CD pipelines. Payloads are HMAC-signed for authenticity verification. Security operations don't have to poll; they get notified.

### 📊 SARIF 2.1.0 Output for SIEM & Code Scanning Integration

Scan results can be exported in [SARIF 2.1.0](https://sarifweb.azurewebsites.net/) format, including `partialFingerprints`, enabling seamless ingestion into **GitHub Code Scanning**, enterprise SIEM dashboards, and vulnerability management platforms, with no middleware required.

### 🔄 Automated Scheduled Scanning

The CheckMate API server includes a built-in scheduler for **continuous, automated repository monitoring**. Security posture is not a point-in-time measurement; CheckMate keeps watching so you don't have to manually trigger audits.

### 🏗️ Flexible Deployment

| Mode | Description |
|---|---|
| **CLI** | Developer workstation, scripting, one-shot audits |
| **Docker** | Container-native scanning in any environment |
| **API Server** | Self-hosted platform with REST API, JWT auth, and SQLite persistence |
| **GitHub Action** | Native CI/CD integration; block secrets before they merge |
| **Desktop App** | GUI application for non-CLI users |
| **MCP Server** | Model Context Protocol (`checkmate mcp serve` and `/v1/mcp`) for AI coding agents |
| **LSP Server** | IDE integration (Language Server Protocol) for in-editor warnings |

---

## Installation

### macOS (via Homebrew)
```bash
brew install adedayo/tap/checkmate
```


### Pre-built Binaries
Download the latest pre-built binaries for your operating system from the [releases page](https://github.com/adedayo/checkmate/releases).

### Docker
```bash
docker pull ghcr.io/adedayo/checkmate
```

### Desktop Application
A graphical desktop version of CheckMate is available: [CheckMate Desktop Application](https://github.com/adedayo/checkmate-app).

---

## Usage

### CLI: Scan Files, Directories, or Git Repositories

```bash
# Scan a local directory
checkmate search /path/to/your/project

# Scan a public or private remote git repository (HTTPS or SSH)
checkmate search https://github.com/example/repository.git
checkmate search --git-token-env GITHUB_TOKEN --git-depth 1 https://github.com/org/private-repo.git
checkmate search --ssh-key ~/.ssh/id_ed25519 git@github.com:org/private-repo.git

# Scan with SARIF output for GitHub Code Scanning
checkmate search --sarif /path/to/project > results.sarif

# Generate a PDF audit report
checkmate search --pdf /path/to/project
```

#### Key CLI Flags

| Flag | Description |
|---|---|
| `--calculate-checksums` | Compute checksums of detected secrets (default: true) |
| `--data-path <dir>` | CheckMate data directory for optional read-only SQLite exceptions (default: `~/.checkmate`) |
| `--diff-only` | With `--staged`, report only findings on added or modified lines (default: true) |
| `--exclude-tests` | Skip test files during scanning |
| `-e, --exclusion <file>` | Use an exclusion YAML configuration file (fails closed with exit 2 if unreadable or invalid) |
| `--fail-on-findings` | Exit `1` when unexcluded findings at or above `--min-confidence` are detected (`2` on error) |
| `--filename <name>` | Virtual filename used with `--stdin` for extension and exclusion matching |
| `--format <fmt>` | Output format: `json`, `text`, `sarif`, `pdf`, or `agent` |
| `--git-depth <n>` | Git clone depth (`1` shallow default, `0` for full history) |
| `--git-token <token>` | Personal access token or password for private HTTPS git repositories |
| `--git-token-env <var>` | Environment variable name containing a git HTTPS access token |
| `--insecure-skip-tls` | Opt-in to skip TLS certificate verification when cloning git repositories |
| `--json` | Generate output in JSON format (default: true) |
| `--min-confidence <lvl>` | Minimum confidence to report or block on: `info`, `low`, `medium`, `high`, `critical` |
| `--no-auto-exclusion` | Disable automatic loading of repo-root `.checkmate.yaml` |
| `--no-db` | Disable reading shared SQLite exceptions |
| `--no-ignore` | Disable `.gitignore` filtering on directory scans and scan all files on disk |
| `--pdf` | Generate a native PDF audit report |
| `-q, --quiet` | Suppress text output when no findings are detected |
| `--redact` | Mask raw secret values in output while keeping SHA-256 checksums |
| `--report-ignored` | Include ignored files and values in reports |
| `--running-commentary` | Stream results as they are found (useful for large repos) |
| `--sample-exclusion` | Generate a sample exclusion YAML file |
| `--sarif` | Generate SARIF 2.1.0 output |
| `--sensitive-files` | List all registered sensitive file types |
| `--sensitive-files-only` | Scan only for sensitive files (certificates, key stores) |
| `-s, --source` | Include source code evidence in results (default: true) |
| `--ssh-key <path>` | Path to an SSH private key file for cloning SSH git repositories |
| `--staged` | Scan staged changes directly from the Git index (ignores unstaged working-tree edits) |
| `--stdin` | Read content to scan from standard input |
| `--tracked-only` | Scan only Git-tracked files (`git ls-files --cached`); exits `2` outside a Git repository |
| `--verbose` | Enable verbose output |

### Git Pre-Commit Hooks, `.gitignore`-Aware Scans & AI-Native CLI Discovery

Block accidental secret leaks before they enter Git history with sub-second staged-diff scanning. Inside a Git repository, directory scans (`checkmate search <dir>`, `checkmate hook run <dir>`) automatically respect `.gitignore` while never skipping Git-tracked files (even if they match `.gitignore`), force-staged blobs (`--staged`), or explicitly passed file arguments:

```bash
# Install CheckMate as your repository's Git pre-commit hook
checkmate hook install

# Run manually on staged Git index changes (redacted terminal output, exit 1 on findings, exit 2 on error)
checkmate hook run

# Pre-push hook: scan strictly Git-tracked files (immune to local .env.local and build directories)
checkmate hook run --tracked-only --min-confidence high

# Full-filesystem audit including untracked gitignored files (.env.local, dist/, .temp/)
checkmate search --no-ignore --format text --redact --fail-on-findings .

# Run with structured AI-agent JSON output (includes status, ignoreMode, redacted findings, and nextSteps)
checkmate hook run --staged --format json

# Pipe content before writing or staging a file
git show :.env | checkmate search --stdin --filename .env --format agent --fail-on-findings

# Self-describing capability manifest for AI coding agents (JSON or Markdown)
checkmate describe
checkmate describe --format markdown
```

You can also integrate CheckMate via the [pre-commit](https://pre-commit.com/) framework using `.pre-commit-hooks.yaml` (`checkmate-staged`, `checkmate-files`, and `checkmate-tracked` for `pre-push`):

```yaml
repos:
  - repo: https://github.com/adedayo/checkmate
    rev: v1.9.0
    hooks:
      - id: checkmate-staged
      - id: checkmate-tracked
        stages: [pre-push]
```

To suppress a verified false positive, add its `sha256` to repo-root `.checkmate.yaml` (`PerFileExcludedHashes` or `GloballyExcludedHashes`), or append `checkmate:ignore` to the line (or `checkmate:ignore-next-line` on the line above).

### Account-Wide GitHub Discovery & Scanning

Point CheckMate at a GitHub user or organisation (`https://github.com/<login>` or `github:<login>`) to enumerate and scan all matching repositories in a single pass:

```bash
# Resolve public repositories with zero configuration (anonymous REST, 60 req/hr per IP)
checkmate account resolve https://github.com/adedayo

# Scan all public repositories of an account (shallow clones, deleted automatically after scan)
checkmate account scan https://github.com/adedayo --format text --redact

# Include private repositories using GITHUB_TOKEN / --git-token / --service (GraphQL, 5,000 pts/hr)
GITHUB_TOKEN=ghp_... checkmate account scan github:acme --format agent --fail-on-findings --min-confidence high

# Filter by repository name globs or override the default 500-repo safety cap
checkmate account resolve https://github.com/acme --include "api-*" --exclude "*-legacy" --max-repos 1000
```

- **Zero-config anonymous mode:** Works out of the box for public repositories and visibly marks results as potentially incomplete so a clean public scan is never mistaken for coverage of private repositories.
- **Safe defaults:** Forks, archived, and disabled repositories are excluded by default (`--include-forks`, `--include-archived`, `--include-disabled` to opt in); clones default to shallow depth-1 (`--full-history` to opt in) and are removed on completion unless `--retain-code` is passed.
- **Go SDK:** Import `github.com/adedayo/checkmate/pkg/sdk` and call `sdk.ParseAccountRef`, `sdk.DefaultAccountFilter`, and `sdk.ResolveAccount` directly.

### API Server

Run CheckMate as a persistent, self-hosted API service:

```bash
checkmate api --port 17283 --data-path ~/.checkmate
```

The API server provides:
- JWT-authenticated REST endpoints for projects, scans, findings, exceptions, and webhooks
- Streamable HTTP MCP endpoint (`POST /v1/mcp`, SSE `GET /v1/mcp`, `DELETE /v1/mcp`), finding context (`GET /v1/findings/{findingId}/context`), checkout cleanup (`DELETE /v1/scans/{scanId}/checkout`), and external agent triage write-back (`PUT /v1/findings/{findingId}/triage`, `POST /v1/scans/{scanId}/triage/batch`, `GET /v1/scans/{scanId}/sanitised`)
- Real-time scan event streaming via WebSocket and Server-Sent Events (SSE)
- Automated scheduled scanning of monitored repositories

For full API capabilities including BYOK AI Triage, Webhook Notifications, and Auditable Exceptions, see the [Features & Capabilities Documentation](docs/features.md), the [REST API Reference](docs/api.md), or the [CheckMate Project Site](https://adedayo.github.io/checkmate/).

### MCP Server (AI Agent Integration)

Drive CheckMate from AI coding agents (GitHub Copilot, Claude Code, Cursor, or CI agents) over stdio or Streamable HTTP with SSE progress:

```bash
# Persistent stdio MCP server (shares ~/.checkmate/checkmate.db with CheckMate App)
checkmate mcp serve

# Ephemeral stdio MCP server for stateless CI or PR reviews (auto-cleans retained checkouts)
checkmate mcp serve --ephemeral
```

Available MCP tools cover the complete triage loop: `checkmate_scan` (synchronous with `_meta.progressToken` or `async: true`, plus `keepCheckout: true` for remote Git URLs), `checkmate_get_scan_status`, `checkmate_get_worklist` (with configurable `samplesPerGroup`), `checkmate_list_findings`, `checkmate_get_finding_context`, `checkmate_cleanup_checkout`, `checkmate_preview_suppression`, `checkmate_triage_batch`, `checkmate_apply_suppression_rule`, and `checkmate_export_sanitised`.

Example MCP client configuration:

```json
{
  "mcpServers": {
    "checkmate": {
      "command": "checkmate",
      "args": ["mcp", "serve"]
    }
  }
}
```

### LSP 3.17 Server (In-Editor Detection & Quick Fixes)

Run CheckMate inside VS Code, Neovim, Zed, Helix, Emacs, or JetBrains IDEs for real-time debounced diagnostics, background workspace scanning, shared SQLite + `.checkmate.yaml` exclusions, and one-click Quick Fix suppressions:

```bash
# Default: shares ~/.checkmate/checkmate.db and workspace .checkmate.yaml
checkmate lspServe

# YAML-only mode without SQLite persistence
checkmate lspServe --no-db --no-workspace-scan
```

See [docs/features.md](docs/features.md#7-in-editor-lsp-317-server-checkmate-lspserve) for copy-paste editor setup snippets.

### Docker

```bash
# Scan a local directory
docker run --rm -v $(pwd):/data ghcr.io/adedayo/checkmate search /data

# Scan a remote git repository
docker run --rm ghcr.io/adedayo/checkmate search https://github.com/example/repository.git
```

### GitHub Actions

Add CheckMate to your CI/CD pipeline to catch secrets before they merge:

```yaml
- name: CheckMate Secret Scan
  uses: adedayo/checkmate@latest
```

### Generating PDF Reports

CheckMate generates executive-ready PDF audit reports natively:

```bash
checkmate search <path> --pdf
```

PDF report generation is **100% native** and runs directly out of the box with zero external dependencies.


---

## Performance & Large Codebases

CheckMate scans files in parallel and gates its rule set behind a literal
prefilter, so that on any given file only the rules that could possibly match
are actually run. On ordinary source this skips well over 90% of the vendor
rule set.

**Tuning never changes results.** The worker count, the prefilter and the
progress interval are performance controls only. The test suite scans a
reference corpus with the prefilter on and off, and at different worker counts,
and requires the findings to be byte-identical. Scans are also deterministic:
the same tree produces the same findings in the same order, on every run and
regardless of which worker happened to finish first.

### Tuning

| Variable | Default | Effect |
| --- | --- | --- |
| `CHECKMATE_SCAN_WORKERS` | `GOMAXPROCS` | Files scanned concurrently. Set to `1` for sequential scanning, or lower to cap CheckMate's footprint on a shared CI runner. |
| `CHECKMATE_PROGRESS_INTERVAL` | `250ms` | Progress reporting interval. Accepts `500ms`, `2s`, or a bare number read as milliseconds. |
| `CHECKMATE_CLONE_CONCURRENCY` | `4` | Repositories cloned at once. |
| `CHECKMATE_DISABLE_PREFILTER` | unset | Set to `1` to run every rule against every file. An escape hatch; should not change results. |
| `CHECKMATE_PRUNE_DIRS` | unset | Comma-separated directory names to skip. Replaces the built-in list; set empty to disable. |

```bash
# Cap CheckMate at 4 workers on a shared build agent
CHECKMATE_SCAN_WORKERS=4 checkmate search ./my-project
```

### Making a dependency-heavy scan faster

Directory pruning is **off by default, deliberately.** Skipping `node_modules`,
`vendor`, `dist` and `.git` is worth roughly 2× on a dependency-heavy tree - but
those directories are scanned today and they hold real secrets: `.npmrc` auth
tokens, API keys baked into `dist/bundle.js`, `https://user:token@host` remotes
in `.git/config`. That is a coverage decision, so it is yours to make rather
than ours:

```bash
CHECKMATE_PRUNE_DIRS='node_modules,vendor,dist,.git' checkmate search ./my-project
```

If a scan is slower than you expect and pruning is not appropriate, the usual
cause is a small number of very large single-line files - minified bundles,
serialised blobs or base64 assets - rather than the file count. Run with
`--verbose` to see which file is being scanned.

For benchmark methodology and the equivalence-testing approach, see
[`docs/testing.md`](docs/testing.md).

---

## Compliance & Governance Use Cases

CheckMate is designed to support the following security and compliance scenarios:

| Use Case | How CheckMate Helps |
|---|---|
| **Pre-commit / PR scanning** | Block secrets from entering the codebase at the source via GitHub Action |
| **Repository-wide audit** | Establish a baseline of existing exposure across all repositories |
| **Continuous monitoring** | Automated, scheduled scans catch regressions as codebases evolve |
| **Audit evidence** | Exception justifications, immutable audit trails, and PDF reports provide auditor-ready documentation |
| **SIEM integration** | SARIF output and webhooks feed findings into enterprise monitoring infrastructure |
| **Air-gapped AI triage** | Reduce analyst workload without sending sensitive code to third-party cloud services |
| **PCI-DSS / SOC 2 / ISO 27001** | Demonstrate active, continuous controls over credential management |

---

## Project Architecture

CheckMate is structured as a layered platform:

```
checkmate/
├── cmd/                       # CLI commands (search, api, mcp, lspServe)
├── pkg/
│   ├── ai/                    # BYOK AI triage client (OpenAI-compatible & Ollama)
│   ├── api/                   # REST API handlers, WebSocket/SSE & Streamable HTTP MCP
│   ├── auth/                  # JWT & scoped API key authentication
│   ├── core/git/              # Unified Git auth (HTTPS/SSH/git_config) & acquisition
│   ├── cron/                  # Scheduled scan automation
│   ├── lsp/                   # Self-contained LSP 3.17 server & Quick Fix suppressions
│   ├── mcp/                   # Model Context Protocol server (stdio + HTTP SSE)
│   ├── plugin/secrets-finder/ # Parallel prefiltered secret detection engine
│   ├── report/                # SARIF 2.1.0 report generation with suppressions
│   ├── reports/pdf/           # Native PDF audit report generation
│   ├── sdk/                   # Importable Go SDK (Scanner, ScanPathWithReport, Finding)
│   ├── store/sqlite/          # CGO-free SQLite persistence with versioned migrations
│   └── triage/                # Shared clustering, suppression preview, context & export
```

The detection engine lives in-repo under [`pkg/plugin/secrets-finder/`](pkg/plugin/secrets-finder/) and is exposed programmatically via [`pkg/sdk/`](pkg/sdk/) so Go tools can embed CheckMate directly without spawning a subprocess or running an HTTP server.

---

## Contributing

Contributions are welcome. Please open an issue or pull request on [GitHub](https://github.com/adedayo/checkmate).

## License

BSD 3-Clause License. See [LICENSE](LICENSE) for details.

**Author:** Dr. Adedayo Adetoye (Dayo): [https://github.com/adedayo](https://github.com/adedayo)
