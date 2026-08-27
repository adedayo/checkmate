# Design: 004-chunk-boundary-minimisation

## The problem in one line

Real files over 4KB diverge between the two engines; synthetic files
constructed to straddle the same boundary do not. **The difference between
"real" and "synthetic" here is the entire unknown.**

## Why the previous two attempts failed

Both probes were built from a hypothesis and then confirmed the hypothesis was
insufficient — which is the correct outcome, but it means the hypothesis is
where the error lies, not the execution.

**`tmp_boundaryprobe`** swept a single secret across the 4096-byte seam in 50
positions. It assumed the mechanism is *"a secret straddles the boundary"*.
Zero divergence. So either the old chunker handled a straddling secret
correctly, or the affected findings were not straddling at all.

**`tmp_boundaryprobe2`** reproduced the shape of `css-select/.../filters.js` —
line lengths, comment placement, the matching region's offset. Zero divergence.
So shape alone is not it either.

The remaining candidates, roughly in order of my confidence:

1. **The old engine's `largeChunk` accumulation path**, which only triggers when
   a 4096-byte read contains *no newline*. Both probes used ordinary multi-line
   content and so may never have entered that branch at all. This is the
   strongest candidate and the cheapest to test — it is a different code path,
   not a different offset.
2. **Interaction with the multiplexer's per-chunk consumer fan-out**, where a
   finding's line/column is computed relative to chunk-local state that a
   boundary resets.
3. **Rule-specific behaviour.** The affected findings are heuristic
   (`SuspiciousOrCommonSecretString`, unbroken-string entropy checks) rather
   than vendor-prefix rules. Entropy over a *truncated* window differs from
   entropy over a whole line — and that would be an offset effect that has
   nothing to do with a secret straddling anything.

Candidate 3 in particular would explain both probe failures cleanly: if the
mechanism is *"entropy scored over a truncated window"*, then sweeping a
well-formed secret across the seam would never reproduce it, because the secret
would score high either way.

## Method: differential delta-debugging

Manual hypothesis-and-probe has now failed twice. Switch to a search that does
not require the hypothesis to be right in advance.

```
  reproducer (5,357 bytes, known to diverge)
        │
        ▼
  ┌─────────────────────────────────────────┐
  │ candidate = reduce(current)             │
  │   scan with HEAD~ engine  ──┐           │
  │   scan with current engine ─┴─ differ?  │
  │      yes → accept reduction, recurse    │
  │      no  → reject, try another cut      │
  └─────────────────────────────────────────┘
        │
        ▼
  minimal input that still diverges
```

The oracle is `diff <(head-engine dump) <(current-engine dump)` being
**non-empty**. `tools/dumpfindings` already emits a canonical sorted line per
finding, so it is directly usable as the oracle with no new tooling.

The pre-change engine comes from a `git worktree` at the commit before 003
landed. Note that `0a2362b` is that commit's child, so the baseline is
`0a2362b~1` — worth pinning explicitly in the harness, because "HEAD" will
drift as soon as anything else is committed.

### Reduction strategy

Standard ddmin over **lines** first (cheap, and the file is line-structured),
then over **bytes** within the surviving lines. Line-level reduction alone will
likely get from 5,357 bytes to something readable; byte-level is what will
expose whether the boundary offset is load-bearing.

**Critical constraint:** reduction must preserve total file size above 4,096
bytes *or* deliberately cross below it, and the harness must record which.
Naively minimising will shrink the file under 4KB, at which point divergence
disappears for the trivial reason that there is no longer a second chunk — and
that is a false minimisation, not a result. Padding must be inert (e.g. a run
of a single repeated character in a comment) and its length recorded.

## The nondeterminism trap

The pre-change engine is **not stable against itself** — two runs over the same
corpus disagreed on `@babel/code-frame/package.json`, differing on whether a
finding was `YAMLSecretAssignment` or `JSONSecretAssignment`. That is defect
D3/D4 surviving in the wild.

For delta-debugging this is not a footnote, it is a correctness hazard: **a
flaky oracle will drive the search into noise** and "minimise" toward a file
that merely triggers the instability. Mitigation: run the baseline engine *n*
times per candidate (n=3 minimum) and only accept a divergence that is stable
across all runs. This makes each step ~4× more expensive and is not optional.

## Definition of done, and of honest failure

Done is `chunkboundary_test.go` failing against the pre-change engine and
passing against the current one, with the fixture committed and the mechanism
named in a comment.

**Failure is an acceptable outcome and must be recorded as one.** If a third
structured attempt does not reproduce, the correct action is to write down that
the mechanism resisted manual probing twice and automated minimisation once,
leave the accepted exception standing explicitly on correlation, and stop. What
must *not* happen is a test that passes for an unrelated reason and is presented
as a guard — the existing `chunkboundary_test.go` header exists precisely
because that trap was nearly fallen into once already.
