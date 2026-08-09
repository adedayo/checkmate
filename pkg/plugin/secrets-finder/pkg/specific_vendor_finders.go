package secrets

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	common "github.com/adedayo/checkmate/pkg/core"
)

/**
Higher recall/confidence patterns from vendors and other well-known secret patterns
*/

var (
	//https://github.blog/2021-04-05-behind-githubs-new-authentication-token-formats/
	//https://github.blog/changelog/2021-03-31-authentication-token-format-updates-are-generally-available/
	githubRegex     = fmt.Sprintf(`(?i:(gh[pousr]_[A-Za-z0-9_]{%d,255}))`, 36) // Current min is 36 chars
	descGithubToken = "Discovered a GitHub OAuth Access Token, posing a risk of compromised GitHub account integrations and data leaks."

	//https://about.gitlab.com/releases/2021/11/22/gitlab-14-5-released/#new-gitlab-access-token-prefix-and-detection
	gitlabRegex     = fmt.Sprintf(`(?i:(glpat-[A-Za-z0-9\-]{%d,255}))`, 20) // Current min is 20 chars
	descGitlabToken = "Identified a GitLab Personal Access Token, risking unauthorized access to GitLab repositories and codebase exposure."

	//https://api.slack.com/authentication/token-types
	slackRegex     = fmt.Sprintf(`(?i:(xox[apbr]-2?[A-Za-z0-9-]{%d,}))`, 24) //examples here https://api.slack.com/authentication/basics longer than 24 chars,
	descSlackToken = "Identified a Slack Bot token, which may compromise bot integrations and communication channel security."

	//https://warehouse.readthedocs.io/api-reference/index.html
	pythonPIRegex     = fmt.Sprintf(`(?i:(pypi-[A-Za-z0-9-=]{%d,}))`, 24)
	descPythonPIToken = "Python Package Index Token"

	// https://www.terraform.io/docs/cloud/users-teams-organizations/api-tokens.html
	terraformPIRegex     = fmt.Sprintf(`(?i:(.+[.]atlasv1[.][A-Za-z0-9-=]{%d,}))`, 24)
	descTerraformPIToken = "Terraform Cloud Token"

	//https://stripe.com/docs/api
	//https://paystack.com/docs/api/#authentication
	stripeRegex     = fmt.Sprintf(`(?i:(?:sk_(?:live|test)|whsec)_[A-Za-z0-9-]{%d,})`, 24) //examples here https://stripe.com/docs/api/authentication longer than 24 chars,
	descStripeToken = "Found a Stripe Access Token, posing a risk to payment processing services and sensitive financial data."

	//https://developer.gocardless.com/api-reference/#oauth-disconnecting-a-user-from-your-app
	goCardlessRegex     = fmt.Sprintf(`(?i:(live_[A-Za-z0-9_-]{%d,255}))`, 20) //
	descGoCardlessToken = "GoCardless Token"

	//https://developer.flutterwave.com/docs/api-keys
	flutterWaveRegex     = fmt.Sprintf(`(?i:((flwseck-|ts_)[A-Za-z0-9_-]{%d,}))`, 20) //
	descFlutterWaveToken = "FlutterWave/MoneyWave API Key"

	connectors = map[string]string{
		"jdbc":       "Database Server",
		"odbc":       "Database Server",
		"s?ftp":      "FTP Server",
		"https?":     "HTTP Service",
		"tcp":        "TCP Service",
		"urn":        "",
		"oracle":     "Oracle Database",
		"mongodb":    "MongoDB Database",
		"postgres":   "Postgres Database",
		"postgresql": "Postgres Database",
		"postgis":    "Postgres GIS Database",
		"mysql":      "MySQL Database",
		"mssql":      "Microsoft SQL Database",
		"mariadb":    "MariaDB Database",
		"amqp":       "AMQP Message Queuing Protocol",
		"db2":        "IBM DB2 Database"}

	connectorKeys = func() (keys []string) {
		for k := range connectors {
			keys = append(keys, k)
		}
		return
	}()

	connectorRegexes = func() map[string]connectorRegex {
		out := make(map[string]connectorRegex)
		for k, v := range connectors {
			out[k] = connectorRegex{
				connector: v,
				re:        regexp.MustCompile(k),
			}
		}

		return out
	}()

	//Connection URI with creds
	connectionURIRegex = fmt.Sprintf(`(?i:((?:%s)[^:]*://[^:]+:[^@]+@)).*`, strings.Join(connectorKeys, "|")) //
	descConnectionURI  = "Connection URI Secret"

	vendorSecretPatterns = map[string]string{
		descGithubToken:      githubRegex,
		descGitlabToken:      gitlabRegex,
		descSlackToken:       slackRegex,
		descStripeToken:      stripeRegex,
		descGoCardlessToken:  goCardlessRegex,
		descConnectionURI:    connectionURIRegex,
		descFlutterWaveToken: flutterWaveRegex,
		descPythonPIToken:    pythonPIRegex,
		descTerraformPIToken: terraformPIRegex,
	}
)

// TODO: Make pre- and post-validating functions in addition to the regex. e.g. string must also contain numbers, upper/lowercases
func makeVendorSecretsFinders(options SecretSearchOptions) []common.ResourceToSecurityDiagnostics {

	// Finders are constructed fresh for each call rather than cached in a
	// package-level slice.
	//
	// The previous global cache was built once from whichever file happened to
	// be scanned first and then shared by every subsequent file, which was
	// wrong in three separate ways:
	//
	//  1. `rif` was captured at construction, so every finding reported the
	//     FIRST scanned file's RepositoryIndex. In a multi-repository scan all
	//     vendor-rule findings were attributed to the wrong repository.
	//  2. The finders carry mutable per-file state (lineIndex, provideSource)
	//     and an append-only consumer list. Every FindSecret call registered
	//     another consumer on the same shared objects, so the list grew without
	//     bound for the lifetime of the process — retaining every aggregator
	//     from every file already scanned, and making each broadcast fan out
	//     over ever more dead consumers.
	//  3. That accumulated state made results depend on how many scans had
	//     already run in the process: the same corpus scanned twice produced
	//     different findings.
	//
	// Constructing per call restores isolation. Phase 2 removes the repeated
	// construction cost by hoisting the finder set into a per-worker
	// ScanContext built once and reset per file.
	//
	// Rules are ordered by sorted provider ID. Ordering is observable:
	// diagnostics.SubsumeOverlapping resolves overlapping findings
	// positionally, so an unstable rule order changes which rule is credited
	// with a secret — and therefore the derived finding ID.
	ids := make([]string, 0, len(vendorSecrets))
	for id := range vendorSecrets {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	finders := make([]common.ResourceToSecurityDiagnostics, 0, len(ids))
	for _, id := range ids {
		sf := secretStringFinder{
			secretFinder{
				ExclusionProvider: options.Exclusions,
				options:           options,
			},
		}
		sf.providerID = id
		sf.res = []*regexp.Regexp{vendorSecrets[id]}
		finders = append(finders, &sf)
	}
	return finders
}

func refineConnectURIDetection(data string) (out string) {
	out = descConnectionURI
	// Iterate connectors in a deterministic order: longest key first, then
	// lexical. Ranging over the map directly meant that a URI matching more
	// than one connector (`postgresql://` matches both the `postgres` and
	// `postgresql` patterns) was described differently on different runs.
	// Longest-first also resolves such overlaps to the most specific
	// connector, which is the evident intent of the table.
	for _, k := range connectorKeysBySpecificity {
		if v, ok := connectorRegexes[k]; ok && v.re.MatchString(data) {
			return fmt.Sprintf("%s Connection URI Secret", v.connector)
		}
	}
	return
}

// connectorKeysBySpecificity orders connector keys longest-first, then
// lexically, giving a stable and maximally specific match order.
var connectorKeysBySpecificity = func() []string {
	keys := make([]string, len(connectorKeys))
	copy(keys, connectorKeys)
	sort.Slice(keys, func(i, j int) bool {
		if len(keys[i]) != len(keys[j]) {
			return len(keys[i]) > len(keys[j])
		}
		return keys[i] < keys[j]
	})
	return keys
}()

type connectorRegex struct {
	connector string
	re        *regexp.Regexp
}
