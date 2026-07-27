// Package sdk provides a clean Go library surface for CheckMate secrets detection.
// Import this package to scan local filesystems or git repositories from any
// Go program — no subprocess, no HTTP, no extra dependencies beyond this module.
//
// Basic usage:
//
//	scanner := sdk.NewScanner(sdk.DefaultOptions())
//	findings, err := scanner.ScanPath(ctx, "./myrepo")
//
//	// Stream findings in real-time:
//	for finding := range scanner.ScanStream(ctx, "./myrepo") {
//	    fmt.Printf("Found %s in %s:%d\n", finding.SecretType, finding.File, finding.Line)
//	}
//
//	// Scan a remote git repo:
//	findings, err = scanner.ScanGitRepo(ctx, "https://github.com/org/repo")
package sdk
