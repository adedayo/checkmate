package secrets

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/adedayo/checkmate/pkg/core/diagnostics"
	"github.com/adedayo/checkmate/pkg/core/util"
)

// knownExtensions covers every extension named in the GetFinderForFileType
// switch, plus representatives of the default branch (including the empty
// extension, which the engine scans for files without one) and mixed case, to
// prove the ToLower normalisation is mirrored too.
var knownExtensions = []string{
	".java", ".scala", ".kt", ".go",
	".c", ".cpp", ".cc", ".c++", ".h++", ".hh", ".hpp", ".hxx",
	".xml",
	".yaml", ".yml", ".json",
	".rb",
	".erb",
	".conf",
	"", ".txt", ".py", ".properties", ".md",
	".JAVA", ".Yml", ".XML", ".Conf",
}

// TestScanContextMatchesGetFinderForFileType is the coupling guard between the
// cached ScanContext and the original per-file constructor.
//
// classForExtension duplicates the GetFinderForFileType switch. A duplicated
// switch is a latent bug: adding a case to one and not the other would
// silently route files at the wrong finder set, changing results without
// failing to compile. This test makes that divergence a build failure by
// comparing, for every known extension, the finder set the context serves
// against the one GetFinderForFileType builds directly.
func TestScanContextMatchesGetFinderForFileType(t *testing.T) {
	options := baselineOptions()
	sc := NewScanContext(options)

	for _, ext := range knownExtensions {
		ext := ext
		t.Run(extName(ext), func(t *testing.T) {
			want := GetFinderForFileType(ext, options)
			got := sc.providers[classForExtension(ext)]

			if got == nil {
				t.Fatalf("no cached provider for extension %q (class %q)", ext, classForExtension(ext))
			}

			wantIDs := providerIDsOf(t, want)
			gotIDs := providerIDsOf(t, got)

			if len(wantIDs) != len(gotIDs) {
				t.Fatalf("finder count mismatch for %q: cached %d, constructed %d",
					ext, len(gotIDs), len(wantIDs))
			}

			for i := range wantIDs {
				if wantIDs[i] != gotIDs[i] {
					t.Fatalf("finder %d mismatch for %q: cached %q, constructed %q",
						i, ext, gotIDs[i], wantIDs[i])
				}
			}
		})
	}
}

// TestScanContextClassesAreDistinct guards the other direction: that the class
// keys are not accidentally collapsed, which would make the guard above pass
// vacuously while every file used the same finder set.
func TestScanContextClassesAreDistinct(t *testing.T) {
	options := baselineOptions()
	sc := NewScanContext(options)

	if len(sc.providers) != 8 {
		t.Fatalf("expected 8 cached provider classes, got %d", len(sc.providers))
	}

	seen := map[string]finderClass{}
	for class, provider := range sc.providers {
		key := strings.Join(providerIDsOf(t, provider), "|")
		if other, dup := seen[key]; dup {
			t.Fatalf("classes %q and %q resolve to identical finder sets", class, other)
		}
		seen[key] = class
	}
}

// TestScanContextIsReusableAcrossFiles is the core Phase 2 correctness claim:
// one context scanning many files must produce exactly what a fresh
// per-file construction would. It specifically catches state leaking between
// files — a finder retaining the previous file's line index, or the
// diagnostic sink accumulating across files.
func TestScanContextIsReusableAcrossFiles(t *testing.T) {
	options := baselineOptions()
	options.ShowSource = true

	files := referenceCorpus()
	sc := NewScanContext(options)

	// Two passes over the same corpus with the same context. A leak would show
	// up as the second pass differing from the first.
	var passes [2][]string
	for pass := 0; pass < 2; pass++ {
		for i, f := range files {
			rif := util.RepositoryIndexedFile{RepositoryIndex: 0, File: f.Path}

			shared := sc.FindSecretsInFile(rif, strings.NewReader(f.Content), extensionOf(f.Path), true)

			fresh := freshScan(rif, f.Content, extensionOf(f.Path), options)

			sharedKeys := summarise(shared)
			freshKeys := summarise(fresh)

			if strings.Join(sharedKeys, "\n") != strings.Join(freshKeys, "\n") {
				t.Fatalf("pass %d, file %d (%s): reused context diverged from fresh construction\ncached:\n%s\nfresh:\n%s",
					pass, i, f.Path,
					strings.Join(sharedKeys, "\n"), strings.Join(freshKeys, "\n"))
			}

			passes[pass] = append(passes[pass], sharedKeys...)
		}
	}

	if strings.Join(passes[0], "\n") != strings.Join(passes[1], "\n") {
		t.Fatal("second pass over the corpus differed from the first: state is leaking between files")
	}
}

// BenchmarkAllocsPerFile is the Phase 2 acceptance measure. Scanning a file
// through a warm ScanContext must not re-pay the ~460 allocations and 64KB of
// finder construction that BenchmarkFinderConstruction records.
func BenchmarkAllocsPerFile(b *testing.B) {
	options := baselineOptions()
	sc := NewScanContext(options)

	content := strings.Repeat("var config = \"nothing to see here\"\n", 200)
	rif := util.RepositoryIndexedFile{RepositoryIndex: 0, File: "bench.go"}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sc.FindSecretsInFile(rif, strings.NewReader(content), ".go", false)
	}
}

// BenchmarkScanContextConstruction records the one-off cost now paid per
// worker rather than per file, so the trade-off stays visible.
func BenchmarkScanContextConstruction(b *testing.B) {
	options := baselineOptions()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if sc := NewScanContext(options); len(sc.providers) != 8 {
			b.Fatal("incomplete context")
		}
	}
}

func freshScan(rif util.RepositoryIndexedFile, content, ext string,
	options SecretSearchOptions) []*diagnostics.SecurityDiagnostic {

	var out []*diagnostics.SecurityDiagnostic
	for d := range FindSecret(rif, strings.NewReader(content), GetFinderForFileType(ext, options), true) {
		out = append(out, d)
	}
	return out
}

func summarise(diags []*diagnostics.SecurityDiagnostic) []string {
	keys := make([]string, 0, len(diags))
	for _, d := range diags {
		keys = append(keys, canonicalKey(canonicalise("", d)))
	}
	return keys
}

// providerIDsOf produces a stable identity for each finder in a provider, in
// declaration order. There is no exported accessor for a finder's provider ID,
// so this reflects over the unexported field when present and falls back to
// the concrete type name. That is enough to detect a class serving the wrong
// finder set or the sets drifting out of order.
func providerIDsOf(t *testing.T, provider MatchProvider) []string {
	t.Helper()
	finders := provider.GetFinders()
	ids := make([]string, 0, len(finders))
	for _, f := range finders {
		ids = append(ids, finderIdentity(f))
	}
	return ids
}

func finderIdentity(f any) string {
	v := reflect.ValueOf(f)
	for v.Kind() == reflect.Ptr && !v.IsNil() {
		v = v.Elem()
	}
	name := reflect.TypeOf(f).String()
	if v.Kind() != reflect.Struct {
		return name
	}
	for _, field := range []string{"providerID", "ProviderID"} {
		if fv := v.FieldByName(field); fv.IsValid() && fv.Kind() == reflect.String {
			return fmt.Sprintf("%s:%s", name, fv.String())
		}
	}
	return name
}

func extensionOf(path string) string {
	if i := strings.LastIndex(path, "."); i >= 0 && !strings.Contains(path[i:], "/") {
		return path[i:]
	}
	return ""
}

func extName(ext string) string {
	if ext == "" {
		return "no-extension"
	}
	return fmt.Sprintf("%s", strings.TrimPrefix(ext, "."))
}
