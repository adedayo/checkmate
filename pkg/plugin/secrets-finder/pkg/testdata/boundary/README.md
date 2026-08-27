# Chunk-boundary divergence fixtures

Inputs on which the pre-`0a2362b` scan engine and the current one produce
different finding sets. They exist because that divergence was found in an
**uncommitted** `node_modules` tree, which `npm ci` would have destroyed
without warning. Captured here so the evidence survives.

These are third-party build artefacts, reproduced verbatim so the bytes still
reproduce the fault. They are test inputs, not project source, and nothing
in the scanner should treat this directory as anything else.

## css-select-filters.js

| | |
|---|---|
| Origin | `css-select@6.0.0`, `dist/esm/pseudo-selectors/filters.js` |
| Found via | `checkmate-app/frontend/node_modules` |
| Size | 5,357 bytes |
| SHA-256 | `7ec4f4d8b92fac7fae14668f760e7e735968f80b497a145a79a04395858b3c19` |
| Licence | BSD-2-Clause (css-select, Felix Böhm) |

Larger than the old chunker's 4,096-byte chunk size, so it is split into two
chunks; that is the precondition for the divergence. Anything that reduces it
below 4,096 bytes destroys the property under test — see task 3.3 in
`openspec/changes/004-chunk-boundary-minimisation/tasks.md`.

## Baseline

The engine this diverges *from* is `0a2362b~1`. Pin that commit explicitly.
`0a2362b` is the child of the commit that changed the chunker, so using
`0a2362b` itself, or `HEAD`, compares the new engine against itself.
