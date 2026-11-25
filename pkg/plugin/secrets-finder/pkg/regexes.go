package secrets

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/adedayo/checkmate/pkg/core/diagnostics"
)

var (
	javaVar         = `[a-zA-Z_$0-9-]`
	quote           = `(?:["'` + "`])"
	notQuote        = `(?:[^'"` + "`]*)"
	minSecretLength = 8

	//freeform text terminated by space
	longUnquotedText        = fmt.Sprintf(`([^\s]{%d,})\s*`, minSecretLength)
	secretUnquotedTextRegex = regexp.MustCompile(fmt.Sprintf(`\s*((?i:%s[^\s]*))\s*`, secretStringIndicators))
	longUnquotedTextRegex   = regexp.MustCompile(longUnquotedText)
	//TODO cater for tripple quoted strings """ ... """ style => try `"{3,3}[^"]*"{3,3}`
	stringLikeValues   = /** standard quote */ `(?s:"(?:[^"\\]|\\.)*")` /** tick */ + `|(?s:'(?:[^'\\]|\\.)*')` + /** backtick */ "|(?s:`(?:[^`\\\\]|\\\\.)*`)"
	secretVarIndicator = `(?i:secret|private|sensitive|confidential|c(?:y|i)pher|crypt|signature|nonce|credential|cert|key|token|salt|auth(?:[^o]|o[^r])+|pass(?:[^e]|e[^ds])+(?:word|phrase)?|ps?wd)`
	secretVar          = fmt.Sprintf(`(%s*?%s%s*?)`, javaVar, secretVarIndicator, javaVar)
	secretVarCompile   = regexp.MustCompile(secretVar)
	//TODO capture unquoted unbroken strings too
	// Disallow newlines, semicolons, and braces inside optional TypeScript type annotations
	// (`: Type`) so object properties like `moduleKeys: foo,` cannot bleed across lines
	// into an unrelated `const invNumber = "..."` assignment below.
	secretAssignment        = regexp.MustCompile(fmt.Sprintf(`%s\s*(?::[^=\n\r;{}]+)?\s*[+]?!?==?\s*(%s)`, secretVar, stringLikeValues))
	envFallbackAssignment   = regexp.MustCompile(fmt.Sprintf(`(?i:(?:Deno\.env\.get\s*\(\s*["'\x60]|process\.env(?:\.|\[["'\x60])|import\.meta\.env(?:\.|\[["'\x60])))\s*%s\s*(?:["'\x60]\s*[\)\]]\s*)?(?:\|\||\?\?)\s*(%s)`, secretVar, stringLikeValues))
	confAssignment          = regexp.MustCompile(fmt.Sprintf(`%s\s*[+]?!?=?\s*(%s)`, secretVar, stringLikeValues))
	secretCPPAssignment     = regexp.MustCompile(fmt.Sprintf(`%s\s*[+]?!?==?\s*L?(%s)`, secretVar, stringLikeValues))
	secretDefine            = regexp.MustCompile(fmt.Sprintf(`(?i:#define)\s+%s\s+L?(%s)`, secretVar, stringLikeValues))
	jsonAssignmentNumOrBool = regexp.MustCompile(fmt.Sprintf(`(?i:"%s"\s*:\s*(\d+|true|false)[^\n]*\n)`, secretVar))                                   //this regex is still unreliable
	jsonAssignmentString    = regexp.MustCompile(fmt.Sprintf(`(?U:%s\s*%s\s*%s\s*:\s*(%s)[^\n]*\n)`, quote, secretVar, quote, stringLikeValues))       //(?U: ... ) to make it ungreedy
	yamlAssignment          = regexp.MustCompile(fmt.Sprintf(`(?U:%s?\s*%s\s*%s?\s*:\s*(%s|[^\n,]*\n),?)`, quote, secretVar, quote, stringLikeValues)) //keep \n in the capture (%s|[^\n]*\n)
	arrowQuoteLeft          = regexp.MustCompile(fmt.Sprintf(`(?U:%s\s*%s\s*%s\s*=>\s*(%s|[^\n]*\n))`, quote, secretVar, quote, stringLikeValues))
	arrowNoQuoteLeft        = regexp.MustCompile(fmt.Sprintf(`(?U:\s*%s\s*=>\s*(%s|[^\n]*\n))`, secretVar, stringLikeValues))
	// arrowAssignment = regexp.MustCompile(fmt.Sprintf(`(?U:%s?\s*%s\s*%s?\s*=>\s*(%s|[^\n]*\n))`, quote, secretVar, quote, quotedString))

	// encodedSecretPatterns = []string{
	// 	`[a-z0-9+/]{0,8}[0-9][a-z0-9+/]{8,}={1,2}`, //Base64-like string
	// 	`[0-9a-fA-F-]{16,}`,                        //Hex-like string
	// }

	encodedSecretPatterns = []string{}

	indexedEncodedSecretPatterns = map[string]string{
		// `base64`: `(?:[a-zA-Z0-9+/]{4}){2,}(?:[a-zA-Z0-9+/]{4}|[a-zA-Z0-9+/]{2}==|[a-zA-Z0-9+/]{3}=)`, //Base64-like string
		`base64`: `[a-zA-Z0-9+/]{0,8}[0-9][a-zA-Z0-9+/]{8,}={1,2}`, //Base64-like string
		`hex`:    `[0-9a-fA-F-]{16,}`,                              //Hex-like string
	}
	commonSecretPatterns   = []string{`password\d?`, `change(?:it|me)`, `postgres`, `admin`, `root`, `qwerty`, `1234567?8?`, `111111`}
	secretStringIndicators = setupSecretStringsIndicators()
	commonSecrets          = []*regexp.Regexp{}
	encodedSecrets         = map[string]*regexp.Regexp{}
	upperCase              = regexp.MustCompile(`[A-Z]`)
	lowerCase              = regexp.MustCompile(`[a-z]`)
	digit                  = regexp.MustCompile(`\d`)
	numbers                = regexp.MustCompile(`^\d+$`)
	rfc4122UUID            = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	isoDateOnlyOrRange     = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}(?:[-_]\d{4}-\d{2}-\d{2})*$`)
	lowercaseSlugPattern   = regexp.MustCompile(`^[a-z][a-z0-9]*(?:[-_][a-z0-9]+)+$`)
	pureHexWithHyphens     = regexp.MustCompile(`^[0-9a-f-]+$`)
	githubActionsExpr      = regexp.MustCompile(`^\$\{\{[\s\S]*\}\}$`)
	pureTemplateExpr       = regexp.MustCompile(`^(?:\$\{[A-Za-z_][A-Za-z0-9_]*\}|\$[A-Za-z_][A-Za-z0-9_]*|\{\{[\s]*[A-Za-z0-9_.$| ()-]+[\s]*\}\})$`)
	space                  = regexp.MustCompile(`\s`)
	special                = regexp.MustCompile(`["!\#$%&'()*+,-./:;<=>?@[\]^_{|}` + "`]")
	longStrings            = regexp.MustCompile(fmt.Sprintf(`((?:%s){%d,})`, stringLikeValues, minSecretLength))
	secretStrings          = regexp.MustCompile(fmt.Sprintf(`(%s%s(?i:%s)%s%s)`, quote, notQuote, secretStringIndicators, notQuote, quote))
	//see https://datatracker.ietf.org/doc/html/rfc7468#section-4
	certIdentifier = regexp.MustCompile(`-----BEGIN ([^-]+)-----`)
	//e.g <x> pasword123 </x>
	secretTagValues = regexp.MustCompile(fmt.Sprintf(`>\s*((?i:%s[^<]*))<`, secretStringIndicators))
	longTagValues   = regexp.MustCompile(fmt.Sprintf(`>([^\s<]{%d,})<`, minSecretLength))
	// longUnbrokenValue = regexp.MustCompile(fmt.Sprintf(`([^\s]{%d,}\s)`, minSecretLength))
	secretTags = regexp.MustCompile(fmt.Sprintf(`<\s*%s\s*>([^<]*)<`, secretVar))

	// testFile = regexp.MustCompile(`(?i:.*/(?:tests?/.*|[^/]*test[^/]*)$)`) //match files with /test/ or /tests/ in the path or with test in the filename
	testFile = regexp.MustCompile(`(?i:.*test.*)`) //match paths that contain the word test anywhere
)

func init() {
	setupCommonSecrets()
	setupEncodedSecrets()
}

func setupCommonSecrets() {
	for _, sec := range commonSecretPatterns {
		commonSecrets = append(commonSecrets, regexp.MustCompile(sec))
	}
}

func setupEncodedSecrets() {
	for ind, sec := range indexedEncodedSecretPatterns {
		encodedSecrets[ind] = regexp.MustCompile(sec)
	}
}

type lazyRegex struct {
	once    sync.Once
	pattern string
	re      *regexp.Regexp
}

func (lr *lazyRegex) get() *regexp.Regexp {
	lr.once.Do(func() {
		if re, err := regexp.Compile(lr.pattern); err == nil {
			lr.re = re
		}
	})
	return lr.re
}

type vendorRuleCatalog struct {
	sortedIDs []string
	patterns  map[string]string
	rules     []lazyRegex
	meta      []*gitleaksRuleMeta
}

func (c *vendorRuleCatalog) regexAt(index int) *regexp.Regexp {
	if index < 0 || index >= len(c.rules) {
		return nil
	}
	return c.rules[index].get()
}

func (c *vendorRuleCatalog) metaAt(index int) *gitleaksRuleMeta {
	if index < 0 || index >= len(c.meta) {
		return nil
	}
	return c.meta[index]
}

// vendorCatalog lazily parses the embedded Gitleaks rule set and merges it
// with CheckMate's built-in vendor rules on first scan use rather than in
// init(). Each individual rule's *regexp.Regexp is compiled lazily on first
// admission behind the literal prefilter, so short-lived CLI/pre-commit runs
// never pay to compile hundreds of rules that cannot match the staged diff.
var vendorCatalog = sync.OnceValue(func() *vendorRuleCatalog {
	patterns := make(map[string]string, len(vendorSecretPatterns)+256)
	metaMap := make(map[string]*gitleaksRuleMeta, 256)
	for desc, sec := range vendorSecretPatterns {
		patterns[desc] = sec
	}

	gitleaksRules := loadGitleaksRules()
	for desc, entry := range gitleaksRules {
		if _, exists := patterns[desc]; !exists {
			patterns[desc] = entry.regex
			metaMap[desc] = entry.meta
		}
	}

	sortedIDs := make([]string, 0, len(patterns))
	for id := range patterns {
		sortedIDs = append(sortedIDs, id)
	}
	sort.Strings(sortedIDs)

	rules := make([]lazyRegex, len(sortedIDs))
	meta := make([]*gitleaksRuleMeta, len(sortedIDs))
	for i, id := range sortedIDs {
		rules[i].pattern = patterns[id]
		meta[i] = metaMap[id]
	}

	return &vendorRuleCatalog{
		sortedIDs: sortedIDs,
		patterns:  patterns,
		rules:     rules,
		meta:      meta,
	}
})

func setupSecretStringsIndicators() string {
	// Iterate in sorted key order. These patterns are joined into an
	// alternation that becomes part of `secretStringIndicators`, which is
	// interpolated into the `secretStrings`, `secretTagValues` and
	// `secretUnquotedTextRegex` patterns. Go's regexp alternation is
	// leftmost-first, so a randomised branch order can change the extent of a
	// match — meaning map iteration order was altering the compiled regexes
	// themselves between runs.
	encodedKeys := make([]string, 0, len(indexedEncodedSecretPatterns))
	for k := range indexedEncodedSecretPatterns {
		encodedKeys = append(encodedKeys, k)
	}
	sort.Strings(encodedKeys)

	// Assign rather than append. This function's result is cached in the
	// `secretStringIndicators` package variable, so in production it runs
	// exactly once — but appending to a package-level slice made it
	// non-idempotent, silently duplicating every pattern on any second call.
	// Assignment makes it safe to invoke repeatedly (as the determinism tests
	// do) and removes a trap for future callers.
	patterns := make([]string, 0, len(encodedKeys))
	for _, k := range encodedKeys {
		patterns = append(patterns, indexedEncodedSecretPatterns[k])
	}
	encodedSecretPatterns = patterns

	indicators := []string{}
	indicators = append(indicators, commonSecretPatterns...)
	indicators = append(indicators, encodedSecretPatterns...)
	return strings.Join(indicators, "|")
}

// MakeCommonExclusions creates an ExcludeDefinition that contains common patterns of files that do not contain secrets
func MakeCommonExclusions() diagnostics.ExcludeDefinition {

	return diagnostics.ExcludeDefinition{
		PathExclusionRegExs: []string{
			`.*[.](?i:html?|css)`, //HTML and CSS files
			`(?:^|.*/)[.]git/.*`,  //skip git files
			`(?:^|.*/)(?i:package-lock|npm-shrinkwrap|packages[.]lock)[.]json`, //JSON dependency lockfiles
			`(?:^|.*/)(?i:pnpm-lock[.]yaml|go[.]sum|gradle[.]lockfile)`,        //integrity-hash lockfiles
			`(?:^|.*/)node_modules/.*`,                                         //node compiled libraries
			`.*[.]md`,                                                          //Markdown files
			`.*[.](?i:lock|xib|storyboard|map|svg)`,                            //lock, UI, source map, and vector files
		},
	}

}

func MergeExclusions(defs ...diagnostics.ExcludeDefinition) (excl diagnostics.ExcludeDefinition) {

	excl.PathRegexExcludedRegExs = make(map[string][]string)
	excl.PerFileExcludedStrings = make(map[string][]string)
	excl.PerFileExcludedHashes = make(map[string][]string)
	for _, def := range defs {
		excl.GloballyExcludedRegExs = unique(append(excl.GloballyExcludedRegExs, def.GloballyExcludedRegExs...))
		excl.GloballyExcludedStrings = unique(append(excl.GloballyExcludedStrings, def.GloballyExcludedStrings...))
		excl.GloballyExcludedHashes = unique(append(excl.GloballyExcludedHashes, def.GloballyExcludedHashes...))
		excl.PathExclusionRegExs = unique(append(excl.PathExclusionRegExs, def.PathExclusionRegExs...))
		for p, v := range def.PathRegexExcludedRegExs {
			if _, present := excl.PathRegexExcludedRegExs[p]; present {
				excl.PathRegexExcludedRegExs[p] = unique(append(excl.PathRegexExcludedRegExs[p], v...))
			} else {
				excl.PathRegexExcludedRegExs[p] = unique(v)
			}
		}
		for p, v := range def.PerFileExcludedStrings {
			if _, present := excl.PerFileExcludedStrings[p]; present {
				excl.PerFileExcludedStrings[p] = unique(append(excl.PerFileExcludedStrings[p], v...))
			} else {
				excl.PerFileExcludedStrings[p] = unique(v)
			}
		}
		for p, v := range def.PerFileExcludedHashes {
			if _, present := excl.PerFileExcludedHashes[p]; present {
				excl.PerFileExcludedHashes[p] = unique(append(excl.PerFileExcludedHashes[p], v...))
			} else {
				excl.PerFileExcludedHashes[p] = unique(v)
			}
		}
	}

	return
}

// unique removes duplicates while preserving first-occurrence order.
//
// It previously returned map-iteration order, which is randomised by Go on
// every run. The result feeds ExcludeDefinition fields that are serialised
// into persisted scan configurations, so identical inputs produced configs
// that differed only by ordering — noisy to diff and impossible to compare.
// Order preservation is both deterministic and the least surprising
// behaviour; membership is unchanged.
func unique(xs []string) []string {
	var nothing struct{}
	seen := make(map[string]struct{}, len(xs))

	out := []string{}
	for _, x := range xs {
		if _, dup := seen[x]; dup {
			continue
		}
		seen[x] = nothing
		out = append(out, x)
	}
	return out
}
