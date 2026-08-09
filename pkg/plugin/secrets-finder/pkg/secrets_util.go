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
	} else if description, isVendor := isVendorSecret(data, secContext.gate.vendorCandidates(data)); isVendor {
		evidence.Description = description
		evidence.Confidence = diagnostics.High

		//some vendor secrets are critical
		switch description {
		case descGithubToken, descSlackToken, descGoCardlessToken, descStripeToken:
			evidence.Confidence = diagnostics.Critical
		case descConnectionURI:
			evidence.Description = refineConnectURIDetection(data)
		}
	} else if isCommonSecret(data) {
		evidence.Description = descCommonSecret
		if validateSpecial(data) {
			evidence.Confidence = diagnostics.High
		} else {
			evidence.Confidence = diagnostics.Medium
		}
	} else if length := float64(len(secret)); length > float64(minSecretLength) && length <= 256 &&
		getShannonEntropy(secret) > entropyCutoff*math.Log2(length) && digit.FindStringSubmatchIndex(secret) != nil {
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
	for i, desc := range sortedVendorSecretIDs {
		if candidates != nil && !candidates.Has(vendorRuleIndices()[i]) {
			continue
		}
		if re, ok := vendorSecrets[desc]; ok && re.FindStringSubmatchIndex(data) != nil {
			return desc, true
		}
	}

	return
}

// vendorRuleIndices maps position in sortedVendorSecretIDs to the rule's bit
// position in a prefilter Set.
//
// Computed once, and positionally aligned rather than looked up by name on
// each iteration: the loop above runs per candidate secret, and a map lookup
// per rule per candidate would put a hash of the description on the hot path
// to save a slice of a few hundred ints.
//
// A rule the matcher does not know — which cannot happen while both are built
// from `vendorSecrets`, but would be a silent disaster if it ever did — maps
// to -1, and Set.Has(-1) is false, so the belt-and-braces here is to treat an
// unknown rule as always-run rather than never-run.
var vendorRuleIndices = sync.OnceValue(func() []int {
	m := vendorMatcher()
	indices := make([]int, len(sortedVendorSecretIDs))
	for i, desc := range sortedVendorSecretIDs {
		if index, ok := m.IndexOf(desc); ok {
			indices[i] = index
		} else {
			indices[i] = -1
		}
	}
	return indices
})

// sortedVendorSecretIDs is the deterministic evaluation order for vendor
// rules, computed once. It is shared by isVendorSecret and by vendor finder
// construction so both resolve overlaps the same way.
//
// It is populated by setupVendorSecrets during package init rather than by a
// variable initialiser: package-level variables are initialised BEFORE init()
// runs, so computing it here would capture `vendorSecrets` while it is still
// empty and silently disable every vendor rule.
var sortedVendorSecretIDs []string

func isCommonSecret(data string) bool {
	for _, re := range commonSecrets {
		if re.FindStringSubmatchIndex(data) != nil {
			return true
		}
	}
	return false
}

// TODO: Decode and scan Base64 Strings
func isEncodedSecret(data string) (description string, isEncoded bool) {
	description = descEncodedSecret
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
