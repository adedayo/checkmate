package secrets

import (
	_ "embed"
	"regexp"

	"github.com/pelletier/go-toml/v2"
)

//go:embed gitleaks.toml
var gitleaksTOML []byte

type GitleaksConfig struct {
	Rules []GitleaksRule `toml:"rules"`
}

type GitleaksRule struct {
	Description string `toml:"description"`
	ID          string `toml:"id"`
	Regex       string `toml:"regex"`
}

func loadGitleaksPatterns() map[string]string {
	var config GitleaksConfig
	err := toml.Unmarshal(gitleaksTOML, &config)
	if err != nil {
		// If the embedded TOML is broken, we panic because it's a compile-time asset issue.
		panic("Failed to parse embedded gitleaks.toml: " + err.Error())
	}

	patterns := make(map[string]string)
	for _, rule := range config.Rules {
		if rule.Regex != "" {
			// Some regexes in Gitleaks use advanced PCRE features (lookaheads, negative lookbehinds)
			// that Go's standard regexp engine does not support. We gracefully skip these.
			_, err := regexp.Compile(rule.Regex)
			if err == nil {
				patterns[rule.Description] = rule.Regex
			}
		}
	}
	return patterns
}
