package prefilter

import (
	"regexp"
	"testing"
)

// FuzzPrefilterSoundness is the safety net for the whole package.
//
// It asserts the single property the scan engine depends on:
//
//	if a rule matches the input, the prefilter admitted that rule.
//
// The opposite direction is deliberately not asserted. Admitting a rule that
// does not match is permitted and expected; it costs one wasted regex
// evaluation. Only a false *negative* loses findings, so that is what this
// test hunts for.
//
// The corpus is the interesting part. Random bytes almost never match a
// secret-detection regex, so a naive fuzzer would explore nothing. The seeds
// below are near-misses and boundary cases built from the rules themselves, so
// the fuzzer starts on the edge of matching and mutates across it.
func FuzzPrefilterSoundness(f *testing.F) {
	patterns := map[string]*regexp.Regexp{
		"github-pat":     regexp.MustCompile(`ghp_[0-9a-zA-Z]{36}`),
		"github-oauth":   regexp.MustCompile(`gho_[0-9a-zA-Z]{36}`),
		"github-multi":   regexp.MustCompile(`(ghp_|gho_|ghu_|ghs_|ghr_)[0-9a-zA-Z]{36}`),
		"aws-access-key": regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		"slack-bot":      regexp.MustCompile(`xox[baprs]-[0-9a-zA-Z-]{10,}`),
		"stripe-live":    regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24}`),
		"gitlab-pat":     regexp.MustCompile(`glpat-[0-9a-zA-Z\-_]{20}`),
		"pem-block":      regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`),
		"aws-secret":     regexp.MustCompile(`(?i)aws_secret_access_key\s*=\s*['"]?[0-9a-zA-Z/+]{40}`),
		"generic-hex":    regexp.MustCompile(`[0-9a-f]{32}`),
		"generic-b64":    regexp.MustCompile(`[a-zA-Z0-9+/]{0,8}[0-9][a-zA-Z0-9+/]{8,}={1,2}`),
		"optional-pfx":   regexp.MustCompile(`(prefix_)?apikey_[0-9]{8}`),
		"nested-alt":     regexp.MustCompile(`(?:(?:corp|team)_(?:token|creds))_[0-9]{6}`),
	}

	m := Build(patterns)

	f.Add("ghp_0123456789012345678901234567890123456")
	f.Add("AKIAIOSFODNN7EXAMPLE")
	f.Add("GHP_0123456789012345678901234567890123456")
	f.Add("xoxb-1234567890-abcdefghij")
	f.Add("sk_live_012345678901234567890123")
	f.Add("glpat-abcdefghij0123456789")
	f.Add("-----BEGIN RSA PRIVATE KEY-----")
	f.Add("-----BEGIN PRIVATE KEY-----")
	f.Add("AWS_SECRET_ACCESS_KEY = \"0123456789012345678901234567890123456789\"")
	f.Add("aws_secret_access_key=0123456789012345678901234567890123456789")
	f.Add("apikey_12345678")
	f.Add("prefix_apikey_12345678")
	f.Add("corp_token_123456")
	f.Add("team_creds_123456")
	f.Add("0123456789abcdef0123456789abcdef")
	f.Add("aGVsbG8gd29ybGQgdGhpcyBpczEyMzQ1Ng==")
	f.Add("package main\n\nfunc main() {}\n")
	f.Add("")
	f.Add("ghp_")
	f.Add("\x00\xff\xfe binary-ish ghp_ content")

	set := m.NewSet()

	f.Fuzz(func(t *testing.T, data string) {
		m.Candidates([]byte(data), set)

		for id, re := range patterns {
			if !re.MatchString(data) {
				continue
			}
			i, ok := m.IndexOf(id)
			if !ok {
				t.Fatalf("rule %q unknown to matcher", id)
			}
			if !set.Has(i) {
				t.Errorf("UNSOUND: rule %q matches input %q but was filtered out (seeds %q)",
					id, data, m.SeedsFor(id))
			}
		}
	})
}
