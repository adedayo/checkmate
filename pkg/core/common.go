package common

import (
	"math"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/adedayo/checkmate/pkg/core/diagnostics"
	"github.com/adedayo/checkmate/pkg/core/util"
)

// IsConfidentialFile indicates whether a file is potentially confidential based on its name or extension, with a narrative indicating
// what sort of file it may be if it is potentially confidential
func IsConfidentialFile(path string) (bool, string) {
	extension := filepath.Ext(path)
	baseName := strings.TrimSuffix(filepath.Base(path), extension)
	if narrative, present := DangerousFileNames[baseName]; present {
		return present, narrative
	}

	if narrative, present := CertsAndKeyStores[extension]; present {
		return present, narrative
	}

	if narrative, present := DangerousExtensions[extension]; present {
		return present, narrative
	}

	if narrative, present := FinancialAndAccountingExtensions[extension]; present && !excludeName(baseName) {
		return present, narrative
	}

	return false, ""
}

func excludeName(basname string) bool {
	switch strings.ToLower(basname) {
	case "readme", "changelog":
		return true
	}
	return false
}

// GetSensitiveFilesDescriptors gets all registered sensitive file descriptions
func GetSensitiveFilesDescriptors() []SensitiveFile {

	length := len(DangerousExtensions) + len(CertsAndKeyStores) + len(DangerousExtensions) +
		len(FinancialAndAccountingExtensions) + 2 //excluded 2 types
	files := make([]SensitiveFile, 0, length)
	for file, description := range DangerousFileNames {
		files = append(files, SensitiveFile{
			Extension:   file,
			Description: description,
		})
	}

	for ext, description := range CertsAndKeyStores {
		files = append(files, SensitiveFile{
			Extension:   ext,
			Description: description,
		})
	}

	for ext, description := range DangerousExtensions {
		files = append(files, SensitiveFile{
			Extension:   ext,
			Description: description,
		})
	}

	for ext, description := range FinancialAndAccountingExtensions {
		files = append(files, SensitiveFile{
			Extension:   ext,
			Description: description,
		})
	}

	files = append(files, SensitiveFile{
		Extension:   "readme[.].*",
		Description: "Readme files are usually non-sensitive",
		Excluded:    true,
	})

	files = append(files, SensitiveFile{
		Extension:   "changelog[.].*",
		Description: "Changelog files are usually non-sensitive",
		Excluded:    true,
	})

	return files
}

// SensitiveFile is a description of a potentially sensitive file based on its name or extension
type SensitiveFile struct {
	//if the value does not start with a . then filename is intended
	Extension   string
	Description string
	Excluded    bool //flag to indicate that this extension or filename should be ignored as non-sensitive
}

func appendMaps(maps ...map[string]string) map[string]string {
	result := make(map[string]string)
	for _, m := range maps {
		for k := range m {
			if v, present := result[k]; present {
				data := []string{}
				if strings.TrimSpace(m[k]) != "" {
					data = append(data, m[k])
				}
				if strings.TrimSpace(v) != "" {
					data = append(data, v)
				}
				result[k] = strings.Join(data, " or ")
			} else {
				result[k] = m[k]
			}
		}
	}
	return result
}

func makeMap(elements string) map[string]string {
	result := make(map[string]string)
	var nothing string
	for _, s := range strings.Split(elements, ",") {
		result["."+s] = nothing
	}
	return result
}

// SourceToSecurityDiagnostics is an interface that describes an object that can consume source and generates security diagnostics
type SourceToSecurityDiagnostics interface {
	util.ResourceConsumer
	diagnostics.SecurityDiagnosticsProvider
}

// PathToSecurityDiagnostics is an interface that describes an object that can consume a file path or URI and generates security diagnostics
type PathToSecurityDiagnostics interface {
	util.PathConsumer
	diagnostics.SecurityDiagnosticsProvider
}

// ResourceToSecurityDiagnostics is an interface that describes an object that consumes arbitrary resource and generates security diagnostics
type ResourceToSecurityDiagnostics interface {
	util.ResourceConsumer
	util.PathConsumer
	diagnostics.SecurityDiagnosticsProvider
}

// RegisterDiagnosticsConsumer registers a callback to consume diagnostics
func RegisterDiagnosticsConsumer(callback func(d *diagnostics.SecurityDiagnostic), providers ...diagnostics.SecurityDiagnosticsProvider) {
	consumer := c{
		callback: callback,
	}
	for _, p := range providers {
		p.AddConsumers(consumer)
	}
}

type c struct {
	callback func(d *diagnostics.SecurityDiagnostic)
}

func (n c) ReceiveDiagnostic(diagnostic *diagnostics.SecurityDiagnostic) {
	n.callback(diagnostic)
}

// DiagnosticsAggregator implements a strategy for aggregating diagnostics, e.g. removing duplicates, overlap, less sever issues etc.
type DiagnosticsAggregator interface {
	AddDiagnostic(diagnostic *diagnostics.SecurityDiagnostic)
	Aggregate() []*diagnostics.SecurityDiagnostic //Called when aggregation strategy is required to be run
}

type simpleDiagnosticAggregator struct {
	// input       chan diagnostics.SecurityDiagnostic
	// diagnostics            []*diagnostics.SecurityDiagnostic
	mutex                  sync.RWMutex
	fileIndexedDiagnostics map[string][]*diagnostics.SecurityDiagnostic
}

func (sda *simpleDiagnosticAggregator) AddDiagnostic(diagnostic *diagnostics.SecurityDiagnostic) {
	// sda.diagnostics = append(sda.diagnostics, diagnostic)
	file := ""
	if diagnostic.Location != nil {
		file = *diagnostic.Location
	}
	sda.mutex.Lock()
	if diags, present := sda.fileIndexedDiagnostics[file]; present {
		sda.fileIndexedDiagnostics[file] = append(diags, diagnostic)
	} else {
		sda.fileIndexedDiagnostics[file] = []*diagnostics.SecurityDiagnostic{diagnostic}
	}
	sda.mutex.Unlock()
}

func (sda *simpleDiagnosticAggregator) Aggregate() (agg []*diagnostics.SecurityDiagnostic) {
	// Iterate file groups in sorted key order.
	//
	// Ranging over the map directly meant the aggregated slice was assembled
	// in randomised group order. That order is observable downstream:
	// diagnostics.SubsumeOverlapping resolves overlapping findings
	// positionally ("keep the earlier index"), so the surviving finding's
	// ProviderID, Range, Justification and Source all depended on map
	// iteration order. Scanning identical input twice could therefore credit
	// the same secret to a different rule, changing the derived finding ID
	// and breaking cross-scan finding identity.
	sda.mutex.RLock()
	keys := make([]string, 0, len(sda.fileIndexedDiagnostics))
	for file := range sda.fileIndexedDiagnostics {
		keys = append(keys, file)
	}
	sort.Strings(keys)

	for _, file := range keys {
		agg = append(agg, removeOverlappingIssues(sda.fileIndexedDiagnostics[file])...)
	}
	sda.mutex.RUnlock()
	return
}

// removeOverlappingIssues drops every finding that is strictly contained by
// another finding of at least equal confidence.
//
// # The predicate
//
// The original implementation was a double loop: for each `di`, scan every
// other `dj` and exclude `di` on the first qualifying one. That is O(n²) in the
// number of findings *in a single file*, which is invisible on ordinary source
// — a handful of findings per file — and catastrophic on one long line. The
// `oneline-json-4mb` adversarial fixture produces **83,888 candidate findings
// in one file**, which subsume down to 2: seven billion range comparisons, 71%
// of the entire scan's CPU time, from a single 4MB file that an attacker can
// commit.
//
// The loop looks order-dependent because of the `break`, but it is not. The
// `break` only stops the search early; the value written is the same for every
// qualifying `dj`, and exclusion is decided against the *original* set rather
// than the surviving one, so it does not cascade. The predicate is therefore
// purely existential:
//
//	exclude di  ⟺  ∃ dj ≠ di :  dj ⊇ di  ∧  conf(di) ≤ conf(dj)  ∧  di ⊉ dj
//
// Since Contains is inclusive, `dj ⊇ di ∧ di ⊉ dj` is exactly "dj properly
// contains di" — equal ranges contain each other and so neither excludes the
// other, which is what preserves genuine duplicates.
//
// # The sweep
//
// Written out with the ranges made explicit, di is excluded iff some dj has
// start ≤ start(di), end ≥ end(di), confidence ≥ conf(di), and is not identical
// in range. Splitting on the start gives two cases, both answerable from a
// running maximum rather than a scan:
//
//	(A) some dj with start < start(di) and end ≥ end(di)
//	(B) some dj with start = start(di) and end > end(di)
//
// The findings are already sorted by start ascending, so a single pass that
// carries "the largest end seen so far, per confidence level" answers (A), and
// the same maximum taken over the current equal-start group answers (B).
// Confidence has five values, so "at least this confident" is a five-element
// loop and not a search.
//
// The result is O(n) after the sort the function already performed, and the
// output is byte-identical: same order, same survivors.
// TestRemoveOverlappingIssuesDifferential proves that against the original
// implementation over randomised inputs.
func removeOverlappingIssues(issues []*diagnostics.SecurityDiagnostic) []*diagnostics.SecurityDiagnostic {
	// Resolve overlaps from a deterministic, content-derived order. The
	// surviving finding's ProviderID, Justification and derived ID all depend
	// on this order, so without it identical input produced different findings
	// between runs. See diagnostics.SortDiagnosticsDeterministically.
	//
	// The sweep below also *requires* the ordering by start index that this
	// provides, so the sort is now load-bearing twice over.
	diagnostics.SortDiagnosticsDeterministically(issues)

	excluded := make([]bool, len(issues))

	// maxEndByConfidence[c] is the largest end offset among findings already
	// swept (strictly earlier start) whose confidence is exactly c.
	//
	// Sentinel is math.MinInt64 rather than 0: offsets are non-negative, but a
	// finding with an empty range at offset 0 would otherwise be
	// indistinguishable from "nothing seen yet" and could exclude itself.
	var maxEndByConfidence [numConfidenceLevels]int64
	var groupMaxEndByConfidence [numConfidenceLevels]int64
	for i := range maxEndByConfidence {
		maxEndByConfidence[i] = math.MinInt64
		groupMaxEndByConfidence[i] = math.MinInt64
	}

	// maxEndAtLeast returns the largest end offset recorded at confidence c or
	// above. Five levels, so the loop is cheaper than maintaining a suffix
	// array and keeps the relationship to the predicate obvious.
	maxEndAtLeast := func(table *[numConfidenceLevels]int64, c diagnostics.Confidence) int64 {
		best := int64(math.MinInt64)
		for level := int(c); level < numConfidenceLevels; level++ {
			if table[level] > best {
				best = table[level]
			}
		}
		return best
	}

	for start := 0; start < len(issues); {
		// Findings sharing a start index are handled as a group, because
		// within a group containment needs a strictly greater end (case B)
		// while across groups an equal end is enough (case A).
		end := start
		startIndex := issues[start].RawRange.StartIndex
		for end < len(issues) && issues[end].RawRange.StartIndex == startIndex {
			end++
		}

		for i := range groupMaxEndByConfidence {
			groupMaxEndByConfidence[i] = math.MinInt64
		}
		for _, d := range issues[start:end] {
			c := confidenceLevel(d.Justification.Headline.Confidence)
			if d.RawRange.EndIndex > groupMaxEndByConfidence[c] {
				groupMaxEndByConfidence[c] = d.RawRange.EndIndex
			}
		}

		for i := start; i < end; i++ {
			di := issues[i]
			conf := diagnostics.Confidence(confidenceLevel(di.Justification.Headline.Confidence))

			// (A) An earlier-starting finding that reaches at least as far.
			if maxEndAtLeast(&maxEndByConfidence, conf) >= di.RawRange.EndIndex {
				excluded[i] = true
				continue
			}
			// (B) A finding starting at the same offset but reaching strictly
			// further. Strictly, because an equal range is mutual containment
			// and excludes neither.
			if maxEndAtLeast(&groupMaxEndByConfidence, conf) > di.RawRange.EndIndex {
				excluded[i] = true
			}
		}

		for level, groupMax := range groupMaxEndByConfidence {
			if groupMax > maxEndByConfidence[level] {
				maxEndByConfidence[level] = groupMax
			}
		}

		start = end
	}

	out := make([]*diagnostics.SecurityDiagnostic, 0, len(issues))
	for i, di := range issues {
		if !excluded[i] {
			out = append(out, di)
		}
	}

	return out
}

// numConfidenceLevels is the size of the diagnostics.Confidence enum
// (Info..Critical).
const numConfidenceLevels = int(diagnostics.Critical) + 1

// confidenceLevel clamps a confidence to a valid table index.
//
// A value outside the enum can only arrive from a caller constructing a
// diagnostic by hand, but the consequence of not clamping is an out-of-range
// panic inside overlap resolution — a crash in the middle of a scan, for a
// finding that is merely mislabelled. Clamping degrades to "treat it as the
// nearest valid confidence", which is what the old linear comparison did
// implicitly.
func confidenceLevel(c diagnostics.Confidence) int {
	if c < diagnostics.Info {
		return int(diagnostics.Info)
	}
	if int(c) >= numConfidenceLevels {
		return numConfidenceLevels - 1
	}
	return int(c)
}

// MakeSimpleAggregator creates a diagnostics aggregator that removes diagnostics whose range is completely
// overlapped by another diagnostic's range
func MakeSimpleAggregator() DiagnosticsAggregator {
	return &simpleDiagnosticAggregator{
		// diagnostics:            make([]*diagnostics.SecurityDiagnostic, 0),
		mutex:                  sync.RWMutex{},
		fileIndexedDiagnostics: make(map[string][]*diagnostics.SecurityDiagnostic),
	}
}
