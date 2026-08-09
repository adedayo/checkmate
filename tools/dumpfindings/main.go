// Command dumpfindings scans a path through SearchSecretsOnPaths and prints one
// canonical line per finding, so two engine versions can be diffed exactly.
package main

import (
	"bufio"
	"fmt"
	"os"
	"sort"

	"github.com/adedayo/checkmate/pkg/core/diagnostics"
	secrets "github.com/adedayo/checkmate/pkg/plugin/secrets-finder/pkg"
)

func main() {
	target := os.Args[1]

	findings, _ := secrets.SearchSecretsOnPaths([]string{target}, secrets.SecretSearchOptions{
		ShowSource:        true,
		CalculateChecksum: true,
		Exclusions:        diagnostics.MakeEmptyExcludes(),
	})

	var lines []string
	for d := range findings {
		loc := ""
		if d.Location != nil {
			loc = *d.Location
		}
		provider := ""
		if d.ProviderID != nil {
			provider = *d.ProviderID
		}
		sha := ""
		if d.SHA256 != nil {
			sha = *d.SHA256
		}
		lines = append(lines, fmt.Sprintf("%s\t%s\t%d:%d-%d:%d\t%s\t%s",
			loc, provider,
			d.Range.Start.Line, d.Range.Start.Character,
			d.Range.End.Line, d.Range.End.Character,
			d.Justification.Headline.Confidence.String(), sha))
	}
	sort.Strings(lines)

	w := bufio.NewWriter(os.Stdout)
	for _, l := range lines {
		if _, err := fmt.Fprintln(w, l); err != nil {
			fmt.Fprintf(os.Stderr, "write: %v\n", err)
			os.Exit(1)
		}
	}
	// A silently-dropped flush would truncate the dump, and a truncated dump
	// compares as a difference. Fail loudly rather than emit a wrong diff.
	if err := w.Flush(); err != nil {
		fmt.Fprintf(os.Stderr, "flush: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "total=%d\n", len(lines))
}
