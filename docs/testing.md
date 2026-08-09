# CheckMate Testing Standards

As part of our commitment to high quality and preventing regressions, CheckMate follows a Test-Driven Development (TDD) workflow. This document outlines our testing standards, preferred libraries, and best practices.

## Core Principles

1. **Test-Driven Development**: Write tests before, or immediately alongside, your code. 
2. **Cover Existing Code**: Ensure all existing capabilities (such as data store logic, config parsing, API endpoints) have adequate test coverage before adding new features.
3. **Deterministic & Fast**: Tests should be fast and deterministic. Use in-memory SQLite for data store tests, and avoid external dependencies (e.g., Docker) where possible for unit and integration testing.
4. **Isolated**: Tests must not rely on the execution order or shared state. Each test should set up and tear down its own requirements.

## Libraries

- **`testing`**: The Go standard library.
- **`github.com/stretchr/testify/require`**: Use this for assertions. `require` immediately fails the test on a failure, preventing confusing subsequent errors caused by the initial failure (unlike `assert` which continues execution).
- **`github.com/stretchr/testify/assert`**: Use this for assertions where you want multiple failures to be reported in a single test run (e.g., asserting on multiple independent fields of a struct).

## Types of Tests

### Unit Tests
- Fast, isolated tests focusing on a single function or struct.
- Prefer `t.Parallel()` for unit tests to ensure fast execution.

### Integration Tests (Data Layer)
- Since we use `modernc.org/sqlite` (pure Go), data layer tests should run against an in-memory database:
  `New("file::memory:?cache=shared")`
- This allows full integration testing of schema migrations, `db.go`, and data models without any external setup or file I/O latency.

## Running Tests

To run all tests locally:
```bash
go test -v ./...
```

To run with coverage:
```bash
go test -cover -v ./...
```

---

## Testing the Scan Engine

The scan engine is optimised aggressively, so its tests are built around one
question: **did the output change?** Performance work is only acceptable here if
the finding set is provably unaffected, and "provably" means a test rather than
a code review.

### Equivalence testing

The engine is tested against a **reference corpus** — a synthetic repository
built to exercise every branch of the file-type dispatch, plus confidential and
test-file fixtures, plus an adversarial set (minified bundles, single-line JSON,
base64 blobs, binaries behind text extensions, deep nesting, symlink loops).

Findings are compared through a **canonicalisation helper** that imposes a total
order, so that parallel scanning cannot introduce sort flakiness and a
comparison failure always means a real difference.

Three separate equivalence properties are asserted:

| Test | Asserts |
| --- | --- |
| `TestScanEquivalence` | The engine reproduces a recorded golden baseline byte-for-byte. |
| `TestPrefilterEquivalence` | Prefiltered and unfiltered scans of the whole corpus agree **with each other**, now. |
| `TestScanIsRepeatable` | Two consecutive scans in one process produce identical results. |

The second is deliberately stronger than the first: a golden baseline only says
the engine matches a recording, which an unsound optimisation introduced
*before* the recording could satisfy. Comparing the two engines against each
other cannot be satisfied that way.

### Soundness of the prefilter

The prefilter is the only component that can **silently remove findings** if it
is wrong — everything else either produces the same output or fails loudly. It
therefore gets stronger testing than its size suggests:

- `FuzzPrefilterSoundness` asserts the one direction that matters: any rule that
  matches must have been admitted. Over-admitting is merely slow;
  under-admitting loses findings. Seed the corpus with near-misses built from
  the rules themselves — random bytes never match a secret regex and explore
  nothing.
- `TestGatedFindersSkipOnlyWhenSeedAbsent` exists because equivalence alone
  cannot show the gate *works*, only that it is harmless: a gate that admitted
  everything would pass every equivalence test while delivering no speed-up.
- `TestPrefilterCoversMostVendorRules` fails if coverage drops below 90%. A drop
  there is a silent *performance* regression, which correctness tests by
  definition cannot catch.

### Differential testing against the previous implementation

When a data structure or algorithm is replaced for speed, the **old
implementation is kept in the test file as the specification** and the new one
is compared against it over randomised inputs — see
`TestLineIndexDifferential` and `TestRemoveOverlappingIssuesDifferential`.

This is preferred over asserting hand-computed expectations, for two reasons:
the reference cannot rot into a paraphrase of what the new code happens to do,
and it exercises far more cases than anyone writes by hand.

Two things matter when writing one:

- **Draw inputs small and dense.** Sparse random ranges rarely overlap or nest,
  which makes an overlap test vacuous while looking thorough. The overlap
  differential draws offsets from `[0,24)` with spans of 0–5 so that identical
  ranges, nested ranges and shared endpoints actually occur.
- **Verify the test by mutation.** Deliberately break the new implementation and
  confirm the differential fails. An equivalence test that cannot fail is worse
  than no test, because it is trusted.

### Determinism

Parallel scanning makes arrival order nondeterministic by construction, so
determinism is a permanent, separately-guarded property rather than an
assumption (`determinism_test.go`). Anything that feeds a regex alternation,
an iteration over a rule map, or an overlap resolution must be explicitly
ordered.

The strongest form of this check is run outside `go test`: scan the same tree in
several independent processes and compare the bytes. Map iteration order varies
per process, so single-process repetition will not catch a rule-ordering defect.

```bash
for i in 1 2 3; do go run ./tools/dumpfindings /path/to/repo > /tmp/run.$i; done
cmp /tmp/run.1 /tmp/run.2 && cmp /tmp/run.2 /tmp/run.3
```

### Benchmark methodology

Benchmarks live alongside the tests and are run with the usual tooling:

```bash
go test -run '^$' -bench 'BenchmarkScan|BenchmarkPrefilter' -benchmem \
  ./pkg/plugin/secrets-finder/pkg/
```

The expensive measurements — large-scale scans, memory profiles and the
adversarial fixtures — are gated behind an environment variable so that ordinary
CI stays inside its timeout:

```bash
CHECKMATE_PERF_BASELINE=1 go test -run 'TestBaseline' -timeout 30m \
  ./pkg/plugin/secrets-finder/pkg/
```

Guidance for interpreting and recording results:

- **Report allocations, not just time.** `-benchmem` is not optional here.
  Allocations per file is the number that predicts behaviour at scale, and it is
  far more stable across machines than nanoseconds.
- **Record what did not improve, and why.** A phase that reports only its wins
  is not a measurement, it is an advertisement. Where a target is missed, the
  reason belongs next to the number.
- **Distinguish "not measured" from "measured and fine".** CPU utilisation was
  inferred from a speed-up for some time before it was measured directly; that
  distinction was recorded rather than glossed.
- **Profile before optimising, and again afterwards.** Two of the largest wins
  in this engine were in functions nobody suspected, and one carefully-planned
  optimisation turned out to target a cost that did not exist.

Real-world scans are the final check, because synthetic corpora do not contain
minified vendor bundles:

```bash
# A dependency tree is a good adversarial corpus that nobody had to write
go run ./tools/dumpfindings ./node_modules
```
