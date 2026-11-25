package secrets

import (
	_ "embed"
	"regexp"
	"regexp/syntax"
	"strings"
	"sync"

	"github.com/pelletier/go-toml/v2"
)

//go:embed gitleaks.toml
var gitleaksTOML []byte

type GitleaksConfig struct {
	Rules []GitleaksRule `toml:"rules"`
}

type GitleaksAllowlist struct {
	Description string   `toml:"description"`
	Condition   string   `toml:"condition"`
	RegexTarget string   `toml:"regexTarget"`
	Regexes     []string `toml:"regexes"`
	Paths       []string `toml:"paths"`
	Stopwords   []string `toml:"stopwords"`
}

type GitleaksRule struct {
	Description string              `toml:"description"`
	ID          string              `toml:"id"`
	Regex       string              `toml:"regex"`
	Entropy     float64             `toml:"entropy"`
	Allowlists  []GitleaksAllowlist `toml:"allowlists"`
}

// gitleaksRuleMeta holds the recall-safe post-match validation metadata
// imported from gitleaks.toml. Allowlist regexes are compiled lazily on first
// match for that rule so process startup remains fast.
type gitleaksRuleMeta struct {
	entropy    float64
	allowlists []GitleaksAllowlist

	compileOnce   sync.Once
	matchAllow    []*regexp.Regexp
	secretAllow   []*regexp.Regexp
	lineAllow     []*regexp.Regexp
	exactStopword map[string]struct{}
}

func (m *gitleaksRuleMeta) compile() {
	m.compileOnce.Do(func() {
		for _, al := range m.allowlists {
			// Skip path-only or compound AND path-conditioned allowlists here;
			// we only apply structural content allowlists that do not depend on
			// skipping entire directories or files.
			if len(al.Paths) > 0 {
				continue
			}
			for _, rx := range al.Regexes {
				re, err := regexp.Compile(rx)
				if err != nil {
					continue
				}
				switch strings.ToLower(strings.TrimSpace(al.RegexTarget)) {
				case "match":
					m.matchAllow = append(m.matchAllow, re)
				case "line":
					m.lineAllow = append(m.lineAllow, re)
				default:
					m.secretAllow = append(m.secretAllow, re)
				}
			}
			// Only record stopwords for exact whole-value matching (never
			// substring matching) so high-entropy random tokens that happen to
			// contain a short English word like "art" or "run" are NEVER dropped.
			if len(al.Stopwords) > 0 {
				if m.exactStopword == nil {
					m.exactStopword = make(map[string]struct{}, len(al.Stopwords))
				}
				for _, sw := range al.Stopwords {
					if s := strings.ToLower(strings.TrimSpace(sw)); s != "" {
						m.exactStopword[s] = struct{}{}
					}
				}
			}
		}
	})
}

// shouldSuppress reports whether a candidate match from a Gitleaks rule should
// be suppressed based on its entropy floor and structural allowlists.
func (m *gitleaksRuleMeta) shouldSuppress(fullMatch, secretVal, line string) bool {
	if m == nil {
		return false
	}
	trimmed := strings.TrimSpace(secretVal)
	if trimmed == "" {
		return true
	}
	if m.entropy > 0 && getShannonEntropy(trimmed) < m.entropy {
		return true
	}

	m.compile()

	if len(m.exactStopword) > 0 {
		if _, isStop := m.exactStopword[strings.ToLower(trimmed)]; isStop {
			return true
		}
	}
	for _, re := range m.secretAllow {
		if re.MatchString(trimmed) {
			return true
		}
	}
	if fullMatch != "" {
		for _, re := range m.matchAllow {
			if re.MatchString(fullMatch) {
				return true
			}
		}
	}
	if line != "" {
		for _, re := range m.lineAllow {
			if re.MatchString(line) {
				return true
			}
		}
	}
	return false
}

type gitleaksRuleEntry struct {
	regex string
	meta  *gitleaksRuleMeta
}

func loadGitleaksRules() map[string]gitleaksRuleEntry {
	var config GitleaksConfig
	err := toml.Unmarshal(gitleaksTOML, &config)
	if err != nil {
		// If the embedded TOML is broken, we panic because it's a compile-time asset issue.
		panic("Failed to parse embedded gitleaks.toml: " + err.Error())
	}

	rules := make(map[string]gitleaksRuleEntry, len(config.Rules))
	for _, rule := range config.Rules {
		if rule.Regex != "" {
			// Some regexes in Gitleaks use advanced PCRE features (lookaheads, negative lookbehinds)
			// that Go's standard regexp engine does not support. Validate with syntax.Parse so we
			// avoid eagerly compiling hundreds of NFA automata at process startup.
			if _, err := syntax.Parse(rule.Regex, syntax.Perl); err == nil {
				var meta *gitleaksRuleMeta
				if rule.Entropy > 0 || len(rule.Allowlists) > 0 {
					meta = &gitleaksRuleMeta{
						entropy:    rule.Entropy,
						allowlists: rule.Allowlists,
					}
				}
				rules[rule.Description] = gitleaksRuleEntry{
					regex: rule.Regex,
					meta:  meta,
				}
			}
		}
	}
	return rules
}
