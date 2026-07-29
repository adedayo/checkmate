package secrets

import (
	"fmt"
	"regexp"
	"strings"

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
	secretAssignment        = regexp.MustCompile(fmt.Sprintf(`%s\s*(?::[^=]+)?\s*[+]?!?==?\s*(%s)`, secretVar, stringLikeValues))
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
	vendorSecrets          = map[string]*regexp.Regexp{}
	upperCase              = regexp.MustCompile(`[A-Z]`)
	lowerCase              = regexp.MustCompile(`[a-z]`)
	digit                  = regexp.MustCompile(`\d`)
	numbers                = regexp.MustCompile(`^\d+$`)
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
	setupVendorSecrets()
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

func setupVendorSecrets() {
	for desc, sec := range vendorSecretPatterns {
		vendorSecrets[desc] = regexp.MustCompile(sec)
	}

	// Integrate Gitleaks rules
	gitleaksPatterns := loadGitleaksPatterns()
	for desc, regexStr := range gitleaksPatterns {
		// Only add it if we don't already have our own rule for it
		// to prevent duplicates or overriding Checkmate specific rules.
		if _, exists := vendorSecrets[desc]; !exists {
			// We already compiled it inside loadGitleaksPatterns to check if Go supports it, 
			// so MustCompile here is safe.
			vendorSecrets[desc] = regexp.MustCompile(regexStr)
		}
	}
}

func setupSecretStringsIndicators() string {
	for _, v := range indexedEncodedSecretPatterns {
		encodedSecretPatterns = append(encodedSecretPatterns, v)
	}
	indicators := []string{}
	indicators = append(indicators, commonSecretPatterns...)
	indicators = append(indicators, encodedSecretPatterns...)
	return strings.Join(indicators, "|")
}

//MakeCommonExclusions creates an ExcludeDefinition that contains common patterns of files that do not contain secrets
func MakeCommonExclusions() diagnostics.ExcludeDefinition {

	return diagnostics.ExcludeDefinition{
		PathExclusionRegExs: []string{
			`.*[.](?i:html?|css)`, //HTML and CSS files
			`.*/[.]git/.*`,        //skip git files
			`.*/(?i:package-lock|npm-shrinkwrap)[.]json`, //package-lock.json and npm-shrinkwrap.json files are high false positive files
			`.*/node_modules/.*`,                         //node compiled libraries
			`.*[.]md`,                                    //Markdown files
			`.*[.](?i:lock|xib|storyboard)`,              //lock, xib and storyboard files
		},
	}

}

func MergeExclusions(defs ...diagnostics.ExcludeDefinition) (excl diagnostics.ExcludeDefinition) {

	excl.PathRegexExcludedRegExs = make(map[string][]string)
	excl.PerFileExcludedStrings = make(map[string][]string)
	for _, def := range defs {
		excl.GloballyExcludedRegExs = unique(append(excl.GloballyExcludedRegExs, def.GloballyExcludedRegExs...))
		excl.GloballyExcludedStrings = unique(append(excl.GloballyExcludedStrings, def.GloballyExcludedStrings...))
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
	}

	return
}

func unique(xs []string) []string {
	var nothing struct{}
	m := make(map[string]struct{})
	for _, x := range xs {
		m[x] = nothing
	}

	out := []string{}
	for x := range m {
		out = append(out, x)
	}
	return out
}
