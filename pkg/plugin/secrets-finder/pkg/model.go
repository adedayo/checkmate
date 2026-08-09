package secrets

import (
	"time"

	"github.com/adedayo/checkmate/pkg/core/diagnostics"
)

// SecretSearchOptions search options for the secret finder plugin
type SecretSearchOptions struct {
	ShowSource            bool                          `json:"ShowSource" yaml:"ShowSource"`
	Exclusions            diagnostics.ExclusionProvider `json:"-" yaml:"-"`
	ConfidentialFilesOnly bool                          `json:"ConfidentialFilesOnly" yaml:"ConfidentialFilesOnly"`
	CalculateChecksum     bool                          `json:"CalculateChecksum" yaml:"CalculateChecksum"`
	Verbose               bool                          `json:"Verbose" yaml:"Verbose"`                   //Verbose logging of file paths about to be scanned
	ReportIgnored         bool                          `json:"ReportIgnored" yaml:"ReportIgnored"`       //if set, generate diagnostics for excluded files/paths and values
	ExcludeTestFiles      bool                          `json:"ExcludeTestFiles" yaml:"ExcludeTestFiles"` //if set, excludes suspected Test Files
	//DisablePrefilter turns off literal prefiltering of vendor rules, running
	//every rule against every file.
	//
	//The prefilter only ever skips rules that provably could not match, so
	//this should make no difference to the findings — which is precisely why
	//it exists: the equivalence test runs the corpus both ways and asserts the
	//results are identical. It is also an operator escape hatch if the
	//prefilter is ever suspected of hiding a finding.
	//
	//Also settable with CHECKMATE_DISABLE_PREFILTER=1.
	DisablePrefilter bool `json:"DisablePrefilter" yaml:"DisablePrefilter"`

	//Workers is the number of files scanned concurrently. Zero (the default)
	//means CHECKMATE_SCAN_WORKERS if set, otherwise GOMAXPROCS.
	//
	//Scanning is a mix of syscall-bound reading and CPU-bound regex matching,
	//so the default is GOMAXPROCS rather than a larger I/O-oriented multiple:
	//once the page cache is warm the regex pass dominates, and oversubscribing
	//there costs scheduler time without buying overlap.
	//
	//Setting this to 1 restores strictly sequential scanning, which is the
	//escape hatch if parallelism is ever suspected of a problem — and is what
	//the equivalence test uses to prove worker count does not affect results.
	Workers int `json:"Workers" yaml:"Workers"`

	//ProgressInterval is how often progress is reported. Zero (the default)
	//means CHECKMATE_PROGRESS_INTERVAL if set, otherwise 250ms.
	//
	//Progress is coalesced onto this interval rather than emitted per file,
	//because the callback fans out to WebSocket clients, the SSE broker or the
	//desktop app's JavaScript bridge, and a per-file callback makes the scan's
	//throughput a function of how many browsers are watching it.
	ProgressInterval time.Duration `json:"ProgressInterval" yaml:"ProgressInterval"`

	//CloneConcurrency is how many repositories are cloned at once. Zero (the
	//default) means CHECKMATE_CLONE_CONCURRENCY if set, otherwise 4.
	//
	//Cloning is network-bound, so the default oversubscribes the CPU
	//deliberately. It is not raised further because the other side is somebody
	//else's Git server, and a scan of a few hundred repositories that opens a
	//few hundred simultaneous clones is indistinguishable from an attack on it.
	CloneConcurrency int `json:"CloneConcurrency" yaml:"CloneConcurrency"`
}
