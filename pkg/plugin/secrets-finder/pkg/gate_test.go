package secrets

// Phase 6 — gate stage guards.
//
// The gate replaced three per-file checks that were previously computed
// independently by each path consumer. Two of them were rewritten from regexes
// into hand-written scans, which is where the risk is: a rewrite that is
// "obviously equivalent" to a regex usually is not, and the failure is silent.
// Each rewrite is therefore pinned against the original regex, which is
// retained in the package for exactly that purpose.

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	common "github.com/adedayo/checkmate/pkg/core"
	"github.com/adedayo/checkmate/pkg/core/diagnostics"
	"github.com/adedayo/checkmate/pkg/core/util"
)

// TestIsTestPathMatchesRegex is the differential for the testFile rewrite.
//
// The regex is `(?i:.*test.*)`, and the tempting translation —
// strings.Contains(strings.ToLower(path), "test") — is WRONG, because Go's
// (?i) applies full Unicode simple case folding and `s` folds with U+017F.
// The corpus below includes that case explicitly; without the fallback in
// isTestPath this test fails, and in production a file would silently stop
// being tagged as a test file.
func TestIsTestPathMatchesRegex(t *testing.T) {
	paths := testPathCorpus()

	matched := 0
	for _, p := range paths {
		want := testFile.MatchString(p)
		if got := isTestPath(p); got != want {
			t.Fatalf("isTestPath(%q) = %v, regex says %v", p, got, want)
		}
		if want {
			matched++
		}
	}

	if matched == 0 || matched == len(paths) {
		t.Fatalf("corpus is degenerate: %d of %d paths matched; "+
			"a constant implementation would pass", matched, len(paths))
	}
}

// TestIsTestPathHandlesUnicodeFold pins the specific trap on its own, so that
// a future "simplification" back to strings.Contains fails with a message
// naming the reason rather than as one line lost in a differential.
func TestIsTestPathHandlesUnicodeFold(t *testing.T) {
	//U+017F LATIN SMALL LETTER LONG S folds with 's' under Unicode simple
	//case folding, so `(?i:test)` matches this.
	const longS = "/src/te\u017Ft/fixture.go"

	if !testFile.MatchString(longS) {
		t.Skip("this Go release no longer folds U+017F with 's'; the trap is gone")
	}
	if !isTestPath(longS) {
		t.Error("isTestPath missed a path the historic regex matches. " +
			"An ASCII-only fold is not equivalent to Go's (?i): U+017F folds with 's'.")
	}
}

func testPathCorpus() []string {
	paths := []string{
		"", "/", "test", "TEST", "Test", "tEsT", "/a/test/b.go", "/a/b_test.go",
		"/a/contest/b.go", "/a/latest/b.go", "/a/attestation/b.go",
		"/a/b.go", "/src/main.go", "/tes/t.go", "/t/e/s/t.go",
		"/a/TESTING/b.go", "/a/b.TEST", "te\u017Ft", "TE\u017FT", "/\u00e9test/a",
		"/a/te\nst/b.go", "/a/test\n/b.go", "/a/\ntest", "test\n",
		"C:\\Users\\me\\Test\\a.go", "/тест/a.go", "/a/тtestт/b.go",
		strings.Repeat("a/", 200) + "test", strings.Repeat("a/", 200) + "b",
	}

	//Random paths built from segments that do and do not contain "test", in
	//varying cases, so the differential explores boundaries the hand-written
	//list would not think of (partial prefixes, overlapping candidates).
	rng := rand.New(rand.NewSource(20260807))
	segments := []string{
		"test", "Test", "TES", "tes", "st", "te", "attest", "src", "pkg",
		"a", "protest", "estimate", "t", "es", "ttestt", "TESt", "\u017F",
	}
	for i := 0; i < 8192; i++ {
		depth := rng.Intn(5) + 1
		parts := make([]string, 0, depth)
		for j := 0; j < depth; j++ {
			parts = append(parts, segments[rng.Intn(len(segments))])
		}
		paths = append(paths, strings.Join(parts, "/"))
	}

	return paths
}

// TestWhitespaceCheckMatchesRegex is the differential for containsWhitespace
// against the `space` regex it replaced.
//
// The subtlety is that Go's `\s` is the Perl class [\t\n\f\r ] and does NOT
// include \v (0x0B) — so a check written from the intuition "is this byte
// whitespace" (unicode.IsSpace, say) would be wrong in one direction on one
// byte, which no realistic sample would ever surface.
func TestWhitespaceCheckMatchesRegex(t *testing.T) {
	//Every single byte, which is what catches the \v case.
	for b := 0; b < 256; b++ {
		s := string([]byte{byte(b)})
		want := space.FindStringSubmatchIndex(s) != nil
		if got := containsWhitespace(s); got != want {
			t.Fatalf("containsWhitespace(%q) = %v, regex says %v (byte 0x%02X)", s, got, want, b)
		}
	}

	rng := rand.New(rand.NewSource(20260807))
	alphabet := []byte("abcXYZ019 \t\n\r\f\v\u0085-_\"'/\\")
	for i := 0; i < 20000; i++ {
		n := rng.Intn(48)
		buf := make([]byte, n)
		for j := range buf {
			buf[j] = alphabet[rng.Intn(len(alphabet))]
		}
		s := string(buf)

		want := space.FindStringSubmatchIndex(s) != nil
		if got := containsWhitespace(s); got != want {
			t.Fatalf("containsWhitespace(%q) = %v, regex says %v", s, got, want)
		}

		//The other call shape that was replaced, which asked the same question
		//by building a slice of every match and comparing it to nil.
		if got, wantAll := !containsWhitespace(s), space.FindAllStringIndex(s, -1) == nil; got != wantAll {
			t.Fatalf("!containsWhitespace(%q) = %v, FindAllStringIndex nil-check says %v", s, got, wantAll)
		}
	}
}

// TestFileExtensionMatchesFilepathExt pins the inlined extension lookup.
func TestFileExtensionMatchesFilepathExt(t *testing.T) {
	paths := append(testPathCorpus(),
		"a.go", ".gitignore", "/a/.gitignore", "/a.b/c", "/a.b/c.d",
		"a.", ".", "..", "/x/y.tar.gz", "no-extension", "/", "",
		"C:\\a.b\\c", "C:\\a.b\\c.d",
	)

	for _, p := range paths {
		if got, want := fileExtension(p), filepath.Ext(p); got != want {
			//The one documented divergence is the Windows separator, which
			//filepath.Ext does not treat as a separator on Unix. If that ever
			//matters, it matters here first.
			if filepath.Separator == '/' && strings.ContainsRune(p, '\\') {
				continue
			}
			t.Fatalf("fileExtension(%q) = %q, filepath.Ext says %q", p, got, want)
		}
	}
}

// countingExclusions records how often the shared per-path checks are asked.
type countingExclusions struct {
	diagnostics.ExclusionProvider
	pathCalls map[string]int
}

func (c *countingExclusions) ShouldExcludePath(p string) bool {
	c.pathCalls[p]++
	return c.ExclusionProvider.ShouldExcludePath(p)
}

// TestGateIsEvaluatedOncePerFile is the point of the whole phase.
//
// With two path consumers registered, the exclusion check ran twice for every
// file — and it is a linear walk of the project's exclusion regexes, so its
// cost grows with the policy the operator has written. Equivalence tests
// cannot see this: doing the work twice produces exactly the right answer.
// Only counting the calls distinguishes a shared gate from a duplicated one.
func TestGateIsEvaluatedOncePerFile(t *testing.T) {
	counting := &countingExclusions{
		ExclusionProvider: diagnostics.MakeEmptyExcludes(),
		pathCalls:         map[string]int{},
	}

	options := baselineOptions()
	options.Exclusions = counting

	consumers := []util.PathConsumer{
		&confidentialFilesFinder{ExclusionProvider: counting, options: options},
		newPathBasedSourceSecretFinder(options),
	}

	root := materialiseCorpus(t, referenceCorpus())
	mux := newGatedPathMultiplexer(counting, consumers...)

	files := util.CollectFiles(t.Context(), []string{filepath.Join(root, "repo-a")}, util.WalkOptions{})
	if len(files) == 0 {
		t.Fatal("no files walked; the assertion would be vacuous")
	}

	for _, f := range files {
		mux.ConsumePath(f)
	}

	for path, calls := range counting.pathCalls {
		if calls != 1 {
			t.Errorf("ShouldExcludePath called %d times for %s; the gate must evaluate it once "+
				"per file no matter how many consumers are registered", calls, path)
		}
	}

	if len(counting.pathCalls) != len(files) {
		t.Errorf("gate evaluated for %d paths, walked %d files",
			len(counting.pathCalls), len(files))
	}
}

// TestGatedConsumersMatchUngatedConsumers asserts the gate changed nothing
// about what the consumers do — only how many times the questions are asked.
//
// The golden baseline already compares the whole engine, but it compares the
// engine against a recording. This compares the gated multiplexer against the
// plain one, right now, over the same files, so a gate that quietly answered
// differently could not hide behind a re-recorded baseline.
func TestGatedConsumersMatchUngatedConsumers(t *testing.T) {
	root := materialiseCorpus(t, referenceCorpus())
	files := util.CollectFiles(t.Context(), []string{
		filepath.Join(root, "repo-a"),
		filepath.Join(root, "repo-b"),
	}, util.WalkOptions{})

	options := baselineOptions()
	options.ReportIgnored = true //exercise the skip-reporting branches too

	collect := func(useGate bool) []string {
		consumers := []util.PathConsumer{
			&confidentialFilesFinder{ExclusionProvider: options.Exclusions, options: options},
			newPathBasedSourceSecretFinder(options),
		}

		var out []string
		sink := func(d *diagnostics.SecurityDiagnostic) {
			out = append(out, fmt.Sprintf("%s|%s|%d|%v|%s",
				derefString(d.Location), derefString(d.ProviderID), d.RepositoryIndex,
				d.Excluded, d.Justification.Headline.Description))
		}

		providers := make([]diagnostics.SecurityDiagnosticsProvider, 0, len(consumers))
		for _, c := range consumers {
			providers = append(providers, c.(diagnostics.SecurityDiagnosticsProvider))
		}
		registerSink(sink, providers...)

		var mux util.PathMultiplexer
		if useGate {
			mux = newGatedPathMultiplexer(options.Exclusions, consumers...)
		} else {
			mux = util.NewPathMultiplexer(consumers...)
		}
		for _, f := range files {
			mux.ConsumePath(f)
		}
		return out
	}

	gated := collect(true)
	plain := collect(false)

	if len(gated) == 0 {
		t.Fatal("no diagnostics produced; the comparison would be vacuous")
	}
	if strings.Join(gated, "\n") != strings.Join(plain, "\n") {
		t.Errorf("gated consumers produced %d diagnostics, ungated %d, and they differ",
			len(gated), len(plain))
	}
}

// TestExtensionlessFileIsScannedFromByteZero covers a defect the gate work
// uncovered rather than introduced.
//
// Extensionless files are sniffed for binary content by reading the first 512
// bytes from the open handle — and that handle was then passed straight to the
// scanner. So every extensionless text file was scanned from byte 512 onwards:
// its first 512 bytes were never searched at all, and every later finding was
// reported 512 characters early, which puts it on the wrong line and, since
// position feeds the finding ID, gives it the wrong identity.
func TestExtensionlessFileIsScannedFromByteZero(t *testing.T) {
	root := t.TempDir()

	//A secret in the first 512 bytes, in a file with no extension.
	secret := `password = "Str0ngAdminPassword99"`
	content := secret + "\n" + strings.Repeat("# filler comment line\n", 200)

	path := filepath.Join(root, "credentials")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}

	run := runScan(t, baselineOptions(), root)

	if len(run.Findings) == 0 {
		t.Fatal("no finding in an extensionless file whose first line is a plaintext password; " +
			"the first 512 bytes are not being scanned")
	}

	for _, f := range run.Findings {
		if f.Range.Start.Line != 0 {
			continue
		}
		return //found it on the first line, at the right position
	}

	t.Errorf("found %d finding(s) but none on line 0, where the secret is; "+
		"positions are shifted, which changes the reported line and the finding ID",
		len(run.Findings))
}

// registerSink wires a diagnostic callback to providers, mirroring what the
// scan entry points do.
func registerSink(sink func(*diagnostics.SecurityDiagnostic), providers ...diagnostics.SecurityDiagnosticsProvider) {
	common.RegisterDiagnosticsConsumer(sink, providers...)
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// Benchmarks below keep both arms — the regex and its replacement — so the
// comparison recorded in tasks.md can be reproduced and cannot rot.

const benchPath = "/home/user/projects/service/src/main/java/com/example/PaymentService.java"

func BenchmarkTestFileRegex(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = testFile.MatchString(benchPath)
	}
}

func BenchmarkIsTestPath(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = isTestPath(benchPath)
	}
}

func BenchmarkWhitespaceRegex(b *testing.B) {
	value := strings.Repeat("A1b2C3d4", 8)
	for i := 0; i < b.N; i++ {
		_ = space.FindAllStringIndex(value, -1) == nil
	}
}

func BenchmarkContainsWhitespace(b *testing.B) {
	value := strings.Repeat("A1b2C3d4", 8)
	for i := 0; i < b.N; i++ {
		_ = containsWhitespace(value)
	}
}
