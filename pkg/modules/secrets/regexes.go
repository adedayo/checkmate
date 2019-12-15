package secrets

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	javaVar                 = `[a-zA-Z_$0-9]`
	quote                   = `(?:["'` + "`])"
	notQuote                = `(?:[^'"` + "`]*)"
	quotedString            = /** standard quote */ `(?s:"(?:[^"\\]|\\.)*")` /** tick */ + `|(?s:'(?:[^'\\]|\\.)*')` + /** backtick */ "|(?s:`(?:[^`\\\\]|\\\\.)*`)"
	secretVarIndicator      = `(?i:secret|private|sensitive|confidential|c(?:y|i)pher|crypt|signature|nonce|credential|key|token|salt|auth(?:[^o]|o[^r])+|pass(?:[^e]|e[^ds])+(?:word|phrase)?|ps?wd)`
	secretVar               = fmt.Sprintf(`(%s*?%s%s*?)`, javaVar, secretVarIndicator, javaVar)
	secretAssignment        = regexp.MustCompile(fmt.Sprintf(`%s\s*(?::[^=]+)?\s*[+]?!?==?\s*(%s)`, secretVar, quotedString))
	confAssignment          = regexp.MustCompile(fmt.Sprintf(`%s\s*[+]?!?=?\s*(%s)`, secretVar, quotedString))
	secretCPPAssignment     = regexp.MustCompile(fmt.Sprintf(`%s\s*[+]?!?==?\s*L?(%s)`, secretVar, quotedString))
	secretDefine            = regexp.MustCompile(fmt.Sprintf(`(?i:#define)\s+%s\s+L?(%s)`, secretVar, quotedString))
	jsonAssignmentNumOrBool = regexp.MustCompile(fmt.Sprintf(`%s?\s*%s\s*%s?\s*:\s*(\d+|(?i:true|false))`, quote, secretVar, quote))
	jsonAssignmentString    = regexp.MustCompile(fmt.Sprintf(`%s?\s*%s\s*%s?\s*:\s*(%s)`, quote, secretVar, quote, quotedString))
	yamlAssignment          = regexp.MustCompile(fmt.Sprintf(`%s?\s*%s\s*%s?\s*:\s*(%s)`, quote, secretVar, quote, quotedString))
	arrowAssignment         = regexp.MustCompile(fmt.Sprintf(`%s?\s*%s\s*%s?\s*=>\s*(%s)`, quote, secretVar, quote, quotedString))

	encodedSecretPatterns = []string{
		`[a-z0-9+/]{0,8}[0-9][a-z0-9+/]{8,}={1,2}`, //Base64-like string
		`[0-9a-fA-F]{16,}`,                         //Hex-like string
	}
	commonSecretPatterns = []string{`password\d?`, `change(?:it|me)`, `postgres`, `admin`, `qwerty`, `1234567?8?`, `111111`}
	commonSecrets        = []*regexp.Regexp{}
	encodedSecrets       = []*regexp.Regexp{}
	upperCase            = regexp.MustCompile(`[A-Z]`)
	lowerCase            = regexp.MustCompile(`[a-z]`)
	digit                = regexp.MustCompile(`\d`)
	space                = regexp.MustCompile(`\s`)
	special              = regexp.MustCompile(`["!\#$%&'()*+,-./:;<=>?@[\]^_{|}` + "`]")
	minSecretLength      = 8
	longStrings          = regexp.MustCompile(fmt.Sprintf(`((?:%s){%d,})`, quotedString, minSecretLength))
	secretStrings        = regexp.MustCompile(fmt.Sprintf(`(%s%s(?i:%s)%s%s)`, quote, notQuote, setupSecretStringsIndicators(), notQuote, quote))
	//e.g <x> pasword123 </x>
	secretTagValues = regexp.MustCompile(fmt.Sprintf(`>\s*((?i:%s[^<]*))<`, setupSecretStringsIndicators()))
	longTagValues   = regexp.MustCompile(fmt.Sprintf(`>([^\s<]{%d,})<`, minSecretLength))
	secretTags      = regexp.MustCompile(fmt.Sprintf(`<\s*%s\s*>([^<]*)<`, secretVar))
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
	for _, sec := range encodedSecretPatterns {
		encodedSecrets = append(encodedSecrets, regexp.MustCompile(sec))
	}
}

func setupSecretStringsIndicators() string {
	indicators := []string{}
	indicators = append(indicators, commonSecretPatterns...)
	indicators = append(indicators, encodedSecretPatterns...)
	return strings.Join(indicators, "|")
}
