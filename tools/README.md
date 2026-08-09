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
