# Spec Delta: Data Store (`data-store`)

**Change:** 008-git-checkout-auth-and-reliability

## `sqlite.DB.RunScan` Requirements

1. **Authenticated cloning:** `RunScan` MUST build an `AuthResolver` backed by `d.GetGitConfigManager()` (honouring each repository's `GitServiceID` and falling back to hostname match and environment tokens) and supply it via `SecretSearchOptions.AuthResolver`.
2. **Acquisition outcome persistence:** `RunScan` MUST persist the scan's `AcquisitionReport` under `scans.additional_info` (`"acquisition": { ... }`).
3. **Total clone failure marks scan `failed`:** When `AcquisitionReport.Succeeded == 0 && AcquisitionReport.Failed > 0`, `RunScan` MUST mark the scan `status = 'failed'` and publish a failure event on the scan broker rather than marking `status = 'complete'` with `total_findings = 0`.
4. **Store accessor:** `PlatformStore` adds `GetScanAcquisitionReport(scanID string) (*gitutils.AcquisitionReport, error)`.
