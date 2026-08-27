# Development tools

Small harnesses used to validate the scan engine. They are not part of the
shipped product and are not covered by the compatibility guarantees in
`openspec/specs/`.

## `dumpfindings`

Scans a path through `SearchSecretsOnPaths` and prints one canonical,
sorted line per finding:

```
<location>\t<providerID>\t<startLine>:<startChar>-<endLine>:<endChar>\t<confidence>\t<sha256>
```

Because the output is sorted and contains no timestamps or run-specific
identifiers, two runs can be compared with `cmp`. This is what makes
cross-process determinism checks and differential testing against another
engine revision possible:

```bash
go run ./tools/dumpfindings /path/to/repo > /tmp/current
git worktree add /tmp/cm-head HEAD
(cd /tmp/cm-head && go run ./tools/dumpfindings /path/to/repo) > /tmp/head
diff /tmp/head /tmp/current
```

Note that arrival order from the scanner is nondeterministic by design; the
sort is what turns that into a comparable artefact. Do not remove it.

## `boundarydiff`

Finds the smallest input on which two engine revisions disagree. Written for
openspec change 004, which proved the chunk-boundary mechanism that change 003
could only correlate.

```bash
go build -o /tmp/bin-current ./tools/dumpfindings
git worktree add --detach /tmp/cm-baseline 0a2362b~1
mkdir -p /tmp/cm-baseline/tools/dumpfindings
cp tools/dumpfindings/main.go /tmp/cm-baseline/tools/dumpfindings/
(cd /tmp/cm-baseline && go build -o /tmp/bin-baseline ./tools/dumpfindings)

go run ./tools/boundarydiff \
  -file pkg/plugin/secrets-finder/pkg/testdata/boundary/css-select-filters.js \
  -baseline /tmp/bin-baseline -current /tmp/bin-current \
  -minimise -out /tmp/reduced.js
```

`dumpfindings` postdates the baseline, so it has to be copied into the older
worktree — it only uses `SearchSecretsOnPaths`, which exists on both sides.

Three properties are worth knowing before trusting its output.

**It runs each engine `-runs` times (default 3) and refuses to answer if either
disagrees with itself.** The pre-change engine is not stable against itself on
some inputs. Delta debugging against a flaky oracle minimises toward the
flakiness and reports it with total confidence.

**Reduction is offset-preserving.** Deleting a line replaces it with spaces of
the same length rather than removing its bytes, so every offset and newline
position is invariant. Without this, ddmin "succeeds" by shrinking the file
below 4,096 bytes, at which point there is no second chunk and the divergence
disappears — a result that looks like a minimal reproducer and is actually the
destruction of the precondition.

**It self-checks before searching**, requiring "diverges" on a known-positive
and "same" on a known-negative. An oracle that answers "diverges" to everything
reduces to noise just as convincingly as a correct one.

## `e2echeck`

Drives the same path the Wails desktop app uses — the SQLite `PlatformStore`'s
`RunScan` with a `SecretScanner` — against a large project, so end-to-end
behaviour can be exercised headlessly.

```bash
go run ./tools/e2echeck /tmp/checkmate-e2e-data /path/to/large/repo
```

Reports wall time, peak heap and finding count. Useful for confirming that a
change behaves on a real dependency tree, which is a far harsher corpus than
anything in the test fixtures.

See `docs/testing.md` for how these fit into the wider testing strategy.
