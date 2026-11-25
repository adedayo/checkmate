package secrets

import (
	"errors"
	"math"
	"sort"
	"strings"
	"sync"

	"github.com/adedayo/checkmate/pkg/core/diagnostics"
	"github.com/adedayo/checkmate/pkg/plugin/secrets-finder/pkg/prefilter"
)

var (
	entropyCutoff = 0.8 //80% of maximum achievable entropy as a cutoff to determine if string is a secret
)

type secretContext struct {
	secret                  string
	higherConfidenceContext bool //e.g. if secret string in a context such as password = "..."
	//gate is the per-worker prefilter, used to skip vendor rules that cannot
	//match this candidate. Nil means no gating, which is what direct callers
	//(tests, the SDK) and the disabled-prefilter path get; the classification
	//is identical either way, only slower.
	gate *ruleGate
}

func detectSecret(secContext secretContext) diagnostics.Evidence {
	secret := secContext.secret

	// log.Printf("Secret: %s", secret)
	evidence := diagnostics.Evidence{
		Description: descSuspiciousSecret,
		Confidence:  diagnostics.Info,
	}

	if !secContext.higherConfidenceContext {
		evidence.Description = descNotSecret
		evidence.Confidence = diagnostics.High
	}

	secret = strings.TrimSpace(secret)
	data := strings.ToLower(secret)
	if data == "true" || data == "false" || data == "" || //the values true or false are unlikely to be secrets
		//skip template expressions (${{ ... }}, ${VAR}, {{ ... }}), OAuth URNs, primitive/type keywords,
		//integrity hashes (sha256-..., h1:...), media data URIs, and decorative dividers
		isNonSecretExpressionOrURN(data) || isDividerString(data) || isNonSecretLiteralOrHash(data) ||
		//secrets seldom start with http or urn (but exclude the connection URI scenario that contains @):
		(strings.HasPrefix(data, "http") || strings.HasPrefix(data, "urn:")) && !strings.Contains(data, "@") ||
		//spaces are unusual to be found in passwords/secrets, exclude values that are only numbers but not longer than 16 characters
		containsWhitespace(data) || (len(data) < 16 && numbers.MatchString(data)) ||
		//anecdotal passwords in config don't typically start with these characters,
		//and if it does but is longer than 45 characters, they probably are security-minded
		//and will know not to put secrets in plaintext, so assume not a secret!
		(strings.Contains(unusualPasswordStartCharacters, string(data[0])) && len(data) > 45) {
		evidence.Description = descNotSecret
		evidence.Confidence = diagnostics.High
	} else if description, isVendor := isVendorSecretWithRaw(secret, data, secContext.gate.vendorCandidates(data)); isVendor {
		evidence.Description = description
		evidence.Confidence = diagnostics.High

		//some vendor secrets are critical
		switch description {
		case descGithubToken, descSlackToken, descGoCardlessToken, descStripeToken:
			evidence.Confidence = diagnostics.Critical
		case descConnectionURI:
			evidence.Description = refineConnectURIDetection(data)
		}
	} else if isCommonSecretInContext(data, secContext.higherConfidenceContext) {
		evidence.Description = descCommonSecret
		if validateSpecial(data) {
			evidence.Confidence = diagnostics.High
		} else {
			evidence.Confidence = diagnostics.Medium
		}
	} else if !isStaticAssetPath(data) && float64(len(secret)) > float64(minSecretLength) && float64(len(secret)) <= 256 &&
		getShannonEntropy(secret) > entropyCutoff*math.Log2(float64(len(secret))) && digit.FindStringSubmatchIndex(secret) != nil {
		//for strings up to 64 characters in length, check that the entropy is at most half the maximum entropy possible for that data
		//also check that there is at least a number in the secret
		evidence.Description = descHighEntropy
		evidence.Confidence = diagnostics.Medium
	} else if desc, isEncoded := isEncodedSecret(data); isEncoded {
		evidence.Description = desc
		evidence.Confidence = diagnostics.High
	} else if validateSpecial(secret) {
		evidence.Description = descSuspiciousSecret
		evidence.Confidence = diagnostics.Medium
	} else if validate(secret) {
		evidence.Description = descSuspiciousSecret
		evidence.Confidence = diagnostics.Low
	}
	return evidence
}

func isVendorSecret(data string, candidates *prefilter.Set) (description string, isVendor bool) {
	return isVendorSecretWithRaw(data, strings.ToLower(data), candidates)
}

func isVendorSecretWithRaw(rawSecret, lowerData string, candidates *prefilter.Set) (description string, isVendor bool) {
	// Evaluate vendor rules in sorted description order.
	//
	// This is a first-match-wins loop, and it previously ranged over the
	// `vendorSecrets` map directly. Several rules legitimately match the same
	// value — a `ghp_…` token matches both CheckMate's own GitHub rule and the
	// imported Gitleaks GitHub rule — so Go's randomised map iteration decided
	// which description was returned. The description also determines the
	// evidence confidence, which in turn drives diagnostics.Dominates during
	// overlap resolution, so a single random choice here changed which finding
	// survived, its range, its source text and its derived finding ID.
	//
	// # Gating
	//
	// `candidates` skips the rules the prefilter has proved cannot match this
	// value. This loop was the single most expensive thing in the engine on
	// adversarial input: it is reached once per candidate secret, and a
	// candidate can be a whole multi-megabyte minified bundle or base64 blob,
	// against which it ran every one of several hundred automata in full. That
	// was 95% of a 74-second scan of one 2MB file.
	//
	// Gating only ever removes rules that could not have matched, so the
	// first-match-wins order among the survivors — and therefore the
	// description, the confidence and every finding property derived from them
	// — is unchanged. A nil set means "no gating", which is what the direct
	// callers in tests and the disabled-prefilter path get.
	cat := vendorCatalog()
	ruleIndices := vendorRuleIndices()
	for i, desc := range cat.sortedIDs {
		if candidates != nil && !candidates.Has(ruleIndices[i]) {
			continue
		}
		re := cat.regexAt(i)
		if re == nil {
			continue
		}
		// Match against rawSecret when case matters (e.g. Shannon entropy on
		// Gitleaks rules); fall back to lowerData for CheckMate's (?i) rules
		// if rawSecret was empty.
		target := rawSecret
		if target == "" {
			target = lowerData
		}
		loc := re.FindStringSubmatchIndex(target)
		if loc == nil {
			continue
		}
		matchedVal := target[loc[0]:loc[1]]
		if len(loc) >= 4 && loc[2] >= 0 && loc[3] >= loc[2] {
			matchedVal = target[loc[2]:loc[3]]
		}
		if !vendorMatchValid(desc, i, target[loc[0]:loc[1]], matchedVal, "") {
			continue
		}
		return desc, true
	}

	return
}

// vendorMatchValid applies recall-safe post-match validation for vendor rules:
// FlutterWave ts_ digit validation and imported Gitleaks entropy/allowlist checks.
func vendorMatchValid(desc string, ruleIndex int, fullMatch, secretVal, line string) bool {
	if desc == descFlutterWaveToken {
		lower := strings.ToLower(strings.TrimSpace(secretVal))
		if strings.HasPrefix(lower, "ts_") && digit.FindStringSubmatchIndex(lower) == nil {
			return false
		}
	}
	if meta := vendorCatalog().metaAt(ruleIndex); meta != nil {
		if meta.shouldSuppress(fullMatch, secretVal, line) {
			return false
		}
	}
	return true
}

// vendorRuleIndices maps position in vendorCatalog().sortedIDs to the rule's
// bit position in a prefilter Set.
//
// Computed once, and positionally aligned rather than looked up by name on
// each iteration: the loop above runs per candidate secret, and a map lookup
// per rule per candidate would put a hash of the description on the hot path
// to save a slice of a few hundred ints.
//
// A rule the matcher does not know — which cannot happen while both are built
// from `vendorCatalog`, but would be a silent disaster if it ever did — maps
// to -1, and Set.Has(-1) is false, so the belt-and-braces here is to treat an
// unknown rule as always-run rather than never-run.
var vendorRuleIndices = sync.OnceValue(func() []int {
	m := vendorMatcher()
	sortedIDs := vendorCatalog().sortedIDs
	indices := make([]int, len(sortedIDs))
	for i, desc := range sortedIDs {
		if index, ok := m.IndexOf(desc); ok {
			indices[i] = index
		} else {
			indices[i] = -1
		}
	}
	return indices
})

func isCommonSecret(data string) bool {
	for _, re := range commonSecrets {
		if re.FindStringSubmatchIndex(data) != nil {
			return true
		}
	}
	return false
}

// isCommonSecretInContext checks common weak credentials while avoiding
// substring false positives on routes, identifiers, and error keys when the
// value is a bare string literal outside a secret-named assignment.
func isCommonSecretInContext(data string, higherConfidenceContext bool) bool {
	if !isCommonSecret(data) {
		return false
	}
	if higherConfidenceContext {
		return true
	}
	// Bare string literal: reject filesystem/URL paths and multi-word
	// snake_case / kebab-case identifiers (e.g. "/admin/users",
	// "forgot_password_email", "project-root-dir") unless the whole value is
	// short and looks like a standalone weak credential.
	if strings.ContainsAny(data, `/\`) {
		return false
	}
	if strings.ContainsAny(data, "_-") {
		// Allow direct credentials like "admin-123" or "password_1" (contains a
		// digit) while skipping pure-word identifiers like "forgot_password_url".
		if digit.FindStringSubmatchIndex(data) == nil {
			return false
		}
	}
	return true
}

// isInsideOAuthURN reports whether byte offset pos in source sits inside a
// `urn:ietf:params:oauth:...` token (such as when a colon-based assignment rule
// splits on `oauth:` or `token-type:` inside an OAuth URN string).
func isInsideOAuthURN(source string, pos int) bool {
	if pos < 0 || pos > len(source) {
		return false
	}
	// Walk backward across contiguous non-whitespace, non-quote characters to
	// find the start of the enclosing token/URN.
	start := pos
	for start > 0 {
		c := source[start-1]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '"' || c == '\'' || c == '`' {
			break
		}
		start--
	}
	end := pos
	for end < len(source) {
		c := source[end]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '"' || c == '\'' || c == '`' {
			break
		}
		end++
	}
	return containsASCIIFold(source[start:end], "urn:ietf:params:oauth:")
}

// isNonSecretExpressionOrURN identifies template variable references
// (${{ ... }}, ${VAR}, $VAR, {{ ... }}) and standard OAuth URNs
// (urn:ietf:params:oauth:...) that are never hardcoded credentials.
// Note: shell fallbacks like ${VAR:-literal} intentionally do NOT match
// pureTemplateExpr so hardcoded fallback values are still scanned.
func isNonSecretExpressionOrURN(lowerTrimmed string) bool {
	if lowerTrimmed == "" {
		return false
	}
	if strings.HasPrefix(lowerTrimmed, "${{") && githubActionsExpr.MatchString(lowerTrimmed) {
		return true
	}
	if (strings.HasPrefix(lowerTrimmed, "$") || strings.HasPrefix(lowerTrimmed, "{{")) &&
		pureTemplateExpr.MatchString(lowerTrimmed) {
		return true
	}
	if strings.Contains(lowerTrimmed, "urn:ietf:params:oauth:") {
		return true
	}
	return false
}

// isNonSecretLiteralOrHash filters primitive/type keywords, content-integrity
// hashes (SRI / Go sumdb / Docker digest), and inline media data URIs.
func isNonSecretLiteralOrHash(lowerTrimmed string) bool {
	switch lowerTrimmed {
	case "null", "undefined", "none", "nil", "string", "number", "boolean",
		"any", "unknown", "void", "never", "bigint", "symbol":
		return true
	}
	for _, prefix := range []string{
		"sha256-", "sha256:", "sha384-", "sha384:", "sha512-", "sha512:",
		"md5:", "h1:", "data:image/", "data:font/", "data:audio/", "data:video/",
	} {
		if strings.HasPrefix(lowerTrimmed, prefix) {
			return true
		}
	}
	return false
}

// isTypeScriptTypeExpr identifies unquoted TypeScript type annotations such as
// `string`, `string | null`, `string | undefined`, or `boolean;` that can be
// matched by YAML-style `key: value` rules in `.ts`/`.tsx` files.
func isTypeScriptTypeExpr(raw string) bool {
	s := strings.TrimSpace(raw)
	s = strings.TrimRight(s, ";,")
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	parts := strings.Split(s, "|")
	for _, p := range parts {
		tok := strings.ToLower(strings.TrimSpace(p))
		switch tok {
		case "string", "number", "boolean", "null", "undefined", "void", "any", "unknown", "never", "bigint", "symbol", "object":
		default:
			return false
		}
	}
	return true
}

// isDividerString reports whether s consists exclusively of decorative divider
// characters (-, =, _, *, #), which would otherwise match hex/base64 heuristics.
func isDividerString(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '-', '=', '_', '*', '#':
		default:
			return false
		}
	}
	return true
}

// isStaticAssetPath identifies relative/absolute static asset paths (such as
// `/assets/chunk-a1b2c3d4e5f67890.js` or `./img/logo-9f86d081.png`) so content
// hashes in asset filenames do not trigger generic entropy or hex heuristics.
// Evaluated only after vendor-token matching so real tokens are never masked.
func isStaticAssetPath(lowerData string) bool {
	if !strings.ContainsAny(lowerData, `/\`) {
		return false
	}
	for _, ext := range []string{".js", ".mjs", ".cjs", ".css", ".map", ".svg", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".woff", ".woff2", ".ico"} {
		if strings.HasSuffix(lowerData, ext) {
			return true
		}
	}
	return false
}

// TODO: Decode and scan Base64 Strings
func isEncodedSecret(data string) (description string, isEncoded bool) {
	description = descEncodedSecret
	if isDividerString(data) || rfc4122UUID.MatchString(data) || isNonSecretLiteralOrHash(data) || isStaticAssetPath(data) {
		return description, false
	}
	// Sorted iteration for determinism. Every branch currently returns the
	// same description, so this is defensive rather than corrective — but the
	// switch invites divergent per-encoding descriptions, at which point map
	// order would silently become observable.
	encodings := make([]string, 0, len(encodedSecrets))
	for ind := range encodedSecrets {
		encodings = append(encodings, ind)
	}
	sort.Strings(encodings)

	for _, ind := range encodings {
		re := encodedSecrets[ind]
		if re.MatchString(data) {
			switch ind {
			case `base64`:
				return description, true
			case `hex`:
				return description, true
			default:
				return description, true
			}
		}
	}
	return description, false
}

func validateSpecial(data string) bool {
	if special.FindStringSubmatchIndex(data) != nil && validate(data) {
		return true
	}
	return false
}

func validate(data string) bool {
	if length := len(data); length >= minSecretLength && length <= 256 &&
		upperCase.FindStringSubmatchIndex(data) != nil &&
		lowerCase.FindStringSubmatchIndex(data) != nil &&
		digit.FindStringSubmatchIndex(data) != nil &&
		!containsWhitespace(data) {
		return true
	}
	return false
}

func getShannonEntropy(data string) float64 {
	var entropy float64
	m := make(map[rune]float64)
	for _, c := range data {
		m[c]++
	}
	if n := float64(len(data)); n > 0 {
		for _, r := range m {
			px := r / n
			entropy += px * math.Log2(px)
		}
		return -entropy
	}
	return entropy
}

type stack struct {
	data []string
}

func (s *stack) push(x string) {
	s.data = append(s.data, x)
}

func (s *stack) pop() (out string, err error) {
	if len(s.data) == 0 {
		return "", errors.New("popping an empty stack")
	}
	index := len(s.data) - 1
	out = s.data[index]
	s.data = s.data[0:index]

	return out, nil
}

func (s *stack) peek() (out string, err error) {
	if len(s.data) == 0 {
		return "", errors.New("peeking an empty stack")
	}
	index := len(s.data) - 1
	out = s.data[index]

	return out, nil
}
