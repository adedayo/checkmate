# Spec Delta: Go SDK (`sdk`)

**Change:** 008-git-checkout-auth-and-reliability

## `pkg/sdk` Additions

- Extend `sdk.Options` with:
  - `GitAuth *gitutils.GitAuth` (optional explicit HTTPS credentials)
  - `AuthResolver gitutils.AuthResolver` (optional custom resolver)
  - `GitDepth int` (default `1`; `0` for full history)
  - `KeepCheckouts bool` (default `false`)
  - `InsecureSkipTLS bool` (default `false`)
- Add `Scanner.ScanPathWithReport(ctx context.Context, paths ...string) (*ScanReport, error)` returning both `Findings []Finding` and `Acquisition gitutils.AcquisitionReport`.
- Update `Scanner.ScanPath` and `Scanner.ScanGitRepo` to return a non-nil error when all targets fail acquisition instead of returning an empty `[]Finding, nil`.
