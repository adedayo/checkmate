package secrets

import (
	"strings"
	"testing"

	"github.com/adedayo/checkmate/pkg/core/diagnostics"
	"github.com/adedayo/checkmate/pkg/core/util"
)

func scanInlineSnippet(filename, content string) []*diagnostics.SecurityDiagnostic {
	opts := SecretSearchOptions{
		ShowSource:        true,
		CalculateChecksum: true,
		Exclusions:        diagnostics.MakeEmptyExcludes(),
	}
	sc := NewScanContext(opts)
	rif := util.RepositoryIndexedFile{RepositoryIndex: 0, File: filename}
	return sc.FindSecretsInFile(rif, strings.NewReader(content), fileExtension(filename), true)
}

func TestGoCardlessBoundaryAnchoring(t *testing.T) {
	// Prefixed tokens like Stripe publishable keys (pk_live_...) and cpt_live_...
	// must NOT false-positive as GoCardless tokens.
	fpSnippet := `
export const stripePublishable = "pk_live_51NxYzAbCdEfGhIjKlMnOpQrStUvWxYz0123456789";
export const customPrefix = "cpt_live_51NxYzAbCdEfGhIjKlMnOpQrStUvWxYz0123456789";
`
	for _, d := range scanInlineSnippet("payments.ts", fpSnippet) {
		if d.ProviderID != nil && *d.ProviderID == descGoCardlessToken {
			t.Errorf("unexpected GoCardless false positive on prefixed token: %+v", d)
		}
		if d.Justification.Headline.Description == descGoCardlessToken {
			t.Errorf("unexpected GoCardless classification on prefixed token: %+v", d)
		}
	}

	// Genuine standalone live_ and sandbox_ GoCardless tokens MUST still be detected.
	tpSnippet := `
export const gcLive = "live_y7VPTOdgFZtFaAS9V8HT3abcd1234567890efgh";
export const gcSandbox = sandbox_y7VPTOdgFZtFaAS9V8HT3abcd1234567890efgh
`
	foundLive := false
	foundSandbox := false
	for _, d := range scanInlineSnippet("gocardless.ts", tpSnippet) {
		if d.Justification.Headline.Description != descGoCardlessToken {
			continue
		}
		if d.Source != nil && strings.Contains(*d.Source, "live_y7VPTOdg") {
			foundLive = true
		}
		if d.Source != nil && strings.Contains(*d.Source, "sandbox_y7VPTOdg") {
			foundSandbox = true
			if strings.HasPrefix(*d.Source, " ") {
				t.Errorf("expected leading space excluded from source, got %q", *d.Source)
			}
		}
	}
	if !foundLive || !foundSandbox {
		t.Fatalf("expected both live_ and sandbox_ GoCardless tokens detected (live=%v sandbox=%v)", foundLive, foundSandbox)
	}
}

func TestDividersAndUUIDsExcludedFromEncodedHeuristic(t *testing.T) {
	for _, divider := range []string{
		"----------------",
		"----------------\\n",
		"================\\r\\n",
		"\\n----------------\\n",
		"================",
		"________________",
		"****************",
		"################",
		"----====****####",
	} {
		if _, encoded := isEncodedSecret(divider); encoded {
			t.Errorf("divider %q must not match isEncodedSecret", divider)
		}
		ev := detectSecret(secretContext{secret: divider, higherConfidenceContext: true})
		if ev.Description != descNotSecret || ev.Confidence != diagnostics.High {
			t.Errorf("divider %q expected High descNotSecret, got %+v", divider, ev)
		}
	}

	for _, u := range []string{
		"550e8400-e29b-41d4-a716-446655440000",
		"A1B2C3D4-E5F6-4789-ABCD-EF0123456789",
	} {
		if _, encoded := isEncodedSecret(u); encoded {
			t.Errorf("RFC 4122 UUID %q must not match isEncodedSecret", u)
		}
	}

	// Genuine hex and base64 secrets must still match.
	if _, encoded := isEncodedSecret("deadbeef0123456789abcdef01234567"); !encoded {
		t.Errorf("expected genuine 32-char hex string to match isEncodedSecret")
	}
	if _, encoded := isEncodedSecret("bXktdmVyeS1zZWNyZXQtdmFsdWUtaGVyZQ=="); !encoded {
		t.Errorf("expected genuine base64 string to match isEncodedSecret")
	}

	// Scanning a TS file with dividers and UUIDs must produce 0 High+ findings.
	ts := `
const sep = "--------------------------------";
const anonKeyId = "550e8400-e29b-41d4-a716-446655440000";
const projectSecretId = "a1b2c3d4-e5f6-4789-abcd-ef0192837465";
`
	for _, d := range scanInlineSnippet("ids.ts", ts) {
		if d.Justification.Headline.Confidence >= diagnostics.High {
			t.Errorf("unexpected High+ finding on divider/UUID: %+v", d)
		}
	}
}

func TestSkipGitHubActionsExprAndOAuthURNs(t *testing.T) {
	yamlSnippet := `
env:
  SUPABASE_SERVICE_ROLE_KEY: "${{ secrets.SUPABASE_SERVICE_ROLE_KEY }}"
  API_TOKEN: ${{secrets.API_TOKEN}}
  SIGNING_PASSPHRASE: "${{ secrets.SIGNING_PASSPHRASE }}"
`
	if diags := scanInlineSnippet("deploy.yml", yamlSnippet); len(diags) != 0 {
		t.Errorf("expected 0 findings on GitHub Actions expressions, got %d: %+v", len(diags), diags)
	}

	tsSnippet := `
const tokenType = "urn:ietf:params:oauth:token-type:access_token";
const grantSecretType = "urn:ietf:params:oauth:grant-type:jwt-bearer";
const authAssertion = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
`
	if diags := scanInlineSnippet("oauth.ts", tsSnippet); len(diags) != 0 {
		for _, d := range diags {
			t.Errorf("unexpected OAuth URN finding: provider=%v source=%v headline=%+v",
				d.ProviderID, d.GetValue(), d.Justification.Headline)
		}
	}
}

func TestEnvFallbackSecretRule(t *testing.T) {
	ts := `
const jwtSecret = Deno.env.get("JWT_SECRET") || "Sup3rS3cr3tFallback!99";
const apiKey = process.env.SUPABASE_SERVICE_KEY ?? "P@ssw0rdFallback123!";
const dbPass = process.env["DB_PASSWORD"] || 'MyHardcodedDbP@ss9';
const lowerDeno = Deno.env.get("MY_API_SECRET") || "hardcoded_prod_secret_123";
const safeUrl = Deno.env.get("SUPABASE_URL") || "http://localhost:54321";
const emptyFallback = Deno.env.get("API_KEY") || "";
`
	diags := scanInlineSnippet("edge.ts", ts)

	highLines := map[int64]bool{}
	for _, d := range diags {
		line := d.Range.Start.Line + 1
		if line == 6 || line == 7 {
			t.Errorf("unexpected finding on safe fallback line %d: %+v", line, d)
		}
		if d.Justification.Headline.Confidence >= diagnostics.High {
			highLines[line] = true
		}
	}

	for _, wantLine := range []int64{2, 3, 4, 5} {
		if !highLines[wantLine] {
			t.Errorf("expected High+ env-fallback finding on line %d, got findings on lines %v", wantLine, highLines)
		}
	}
}

func TestTruePositiveRecallNotRegressed(t *testing.T) {
	// Every case below represents a genuine secret that MUST remain detected
	// after all false-positive guards (proving we do not over-rotate like tools
	// that drop high-entropy secrets containing English stopwords or weak
	// hardcoded passwords).
	cases := []struct {
		name     string
		file     string
		snippet  string
		minLevel diagnostics.Confidence
	}{
		{
			name:     "AWS access key (non-example)",
			file:     "aws.ts",
			snippet:  `const awsKey = "` + "AKIA" + `W3MEGN7X9K2PQ4RT";`,
			minLevel: diagnostics.High,
		},
		{
			name:     "GitHub PAT",
			file:     "gh.ts",
			snippet:  `const gh = "` + "ghp_" + `0123456789abcdef0123456789abcdef0123";`,
			minLevel: diagnostics.Critical,
		},
		{
			name:     "GitLab PAT",
			file:     "gl.ts",
			snippet:  `const gl = "` + "glpat-" + `AbCdEfGhIjKlMnOpQrSt";`,
			minLevel: diagnostics.High,
		},
		{
			name:     "Stripe live secret key",
			file:     "pay.ts",
			snippet:  `const sk = "` + "sk_live_" + `4eC39HqLyjWDarjtT1zdp7dc";`,
			minLevel: diagnostics.Critical,
		},
		{
			name:     "Slack bot token",
			file:     "bot.ts",
			snippet:  `const slack = "` + "xoxb-" + `333649436676-799261852869-clFJVVIaoJahpORboa3Ba2al";`,
			minLevel: diagnostics.Critical,
		},
		{
			name:     "FlutterWave flwseck and ts_ with digits",
			file:     "fw.ts",
			snippet:  `const fw1 = "flwseck-1234567890abcdef1234567890"; const fw2 = "ts_9a8b7c6d5e4f3a2b1c0d9e8f";`,
			minLevel: diagnostics.High,
		},
		{
			name:     "Terraform Cloud token",
			file:     "tf.hcl",
			snippet:  `token = "abcdefgh123456.atlasv1.0123456789abcdefghijklmnopqrstuvwxyz"`,
			minLevel: diagnostics.High,
		},
		{
			name:     "High-entropy API key containing Gitleaks stopwords (art, run, app)",
			file:     "api.ts",
			snippet:  `const apiKey = "x9K2m_art_8vQ4n_run_7pL3zR_app_5mW1q";`,
			minLevel: diagnostics.High,
		},
		{
			name:     "Bare 32-char hex secret in assignment",
			file:     "hmac.ts",
			snippet:  `const hmacSecret = "9f86d081884c7d659a2feaa0c55ad015";`,
			minLevel: diagnostics.High,
		},
		{
			name:     "Bare base64 secret in assignment",
			file:     "enc.ts",
			snippet:  `const encKey = "bXktdmVyeS1zZWNyZXQtdmFsdWUtaGVyZQ==";`,
			minLevel: diagnostics.High,
		},
		{
			name:     "Weak hardcoded passwords in secret assignments",
			file:     "db.ts",
			snippet:  `const password = "admin"; const dbPassword = "password123";`,
			minLevel: diagnostics.Medium,
		},
		{
			name:     "Postgres connection URI with credentials",
			file:     "db.env",
			snippet:  `DATABASE_URL=postgres://svc:P@ss!word@db.prod.internal:5432/app`,
			minLevel: diagnostics.High,
		},
		{
			name:     "Shell default-fallback secret ${VAR:-literal} must NOT be skipped",
			file:     "deploy.sh",
			snippet:  `JWT_SECRET="${JWT_SECRET:-Sup3rS3cr3tFallback!99}"`,
			minLevel: diagnostics.High,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			diags := scanInlineSnippet(tc.file, tc.snippet)
			maxConf := diagnostics.Info - 1
			for _, d := range diags {
				if d.Justification.Headline.Confidence > maxConf {
					maxConf = d.Justification.Headline.Confidence
				}
			}
			if len(diags) == 0 || maxConf < tc.minLevel {
				t.Fatalf("recall regression for %q: got %d findings (max confidence %v), want >= %v",
					tc.name, len(diags), maxConf, tc.minLevel)
			}
		})
	}

	// PEM bundle containing BOTH a public certificate and a private key MUST remain Critical.
	mixedPEM := "-----BEGIN CERTIFICATE-----\nMIIBIjANBgkq\n-----END CERTIFICATE-----\n" +
		"-----BEGIN PRIVATE KEY-----\nMIIEvQIBADAN\n-----END PRIVATE KEY-----\n"
	ev, ok := CheckConfidentialBytes("certs/bundle.pem", []byte(mixedPEM), false)
	if !ok || ev.Confidence != diagnostics.Critical {
		t.Fatalf("expected mixed cert+private-key PEM to be Critical, got ok=%v ev=%+v", ok, ev)
	}
}

func TestFalsePositiveGuards(t *testing.T) {
	// 1. Gitleaks generic-api-key structural allowlists & entropy floor.
	genericFP := `
const primary_key = "user_account_identifier";
const api_version = "2026-01-01";
const keyboard_shortcut = "cmd_shift_palette";
const awsDocExample = "AKIAIOSFODNN7EXAMPLE";
`
	for _, d := range scanInlineSnippet("benign.ts", genericFP) {
		if d.Justification.Headline.Confidence >= diagnostics.High {
			t.Errorf("unexpected High+ FP on benign generic keys / AWS example: provider=%v source=%q headline=%+v",
				d.ProviderID, d.GetValue(), d.Justification.Headline)
		}
	}

	// 2. FlutterWave ts_ boundary and digit guard.
	fwFP := `
const a = "events_processing_configuration_handler";
const b = "assets_manifest_generation_pipeline";
const c = "ts_processing_configuration_handler";
`
	for _, d := range scanInlineSnippet("identifiers.ts", fwFP) {
		if d.Justification.Headline.Description == descFlutterWaveToken {
			t.Errorf("unexpected FlutterWave FP on identifier: %q", d.GetValue())
		}
	}

	// 3. Connection URI must not cross '/' in URLs containing port + @handle.
	urlFP := `const profile = "https://example.com:443/users/@alice";`
	if diags := scanInlineSnippet("routes.ts", urlFP); len(diags) != 0 {
		t.Errorf("unexpected Connection URI FP on URL with port and @handle: %+v", diags)
	}

	// 4. Pure template refs, TS type annotations, integrity hashes, media data URIs, hashed asset paths.
	tsFP := `
interface AuthConfig {
  apiKey: string | null;
  secret: undefined;
  token: boolean;
}
const envRef1 = "${SUPABASE_SERVICE_ROLE_KEY}";
const envRef2 = "$JWT_SECRET";
const helmRef = "{{ .Values.apiKey }}";
const sri = "sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";
const sumHash = "h1:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=";
const img = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=";
const bundle = "/assets/chunk-a1b2c3d4e5f67890.js";
const route = "/admin/dashboard";
const errCode = "forgot_password_email";
const rootDir = "project-root-dir";
`
	for _, d := range scanInlineSnippet("types.ts", tsFP) {
		if d.Justification.Headline.Confidence >= diagnostics.Medium {
			t.Errorf("unexpected Medium+ FP on types/templates/hashes/routes: provider=%v source=%q headline=%+v",
				d.ProviderID, d.GetValue(), d.Justification.Headline)
		}
	}

	// 5. Public-only X.509 certificate downgrades to Info (not High/Critical).
	pubCert := "-----BEGIN CERTIFICATE-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n-----END CERTIFICATE-----\n"
	ev, ok := CheckConfidentialBytes("certs/ca.pem", []byte(pubCert), false)
	if !ok || ev.Confidence != diagnostics.Info {
		t.Fatalf("expected public-only X.509 certificate to be Info, got ok=%v ev=%+v", ok, ev)
	}

	// 6. MakeCommonExclusions excludes lockfiles/maps/svgs while keeping minified JS bundles scanned.
	exclDef := MakeCommonExclusions()
	excl, err := diagnostics.CompileExcludes(diagnostics.ExcludeContainer{ExcludeDef: &exclDef})
	if err != nil {
		t.Fatalf("CompileExcludes failed: %v", err)
	}
	for _, shouldSkip := range []string{"go.sum", "sub/go.sum", "pnpm-lock.yaml", "gradle.lockfile", "dist/app.js.map", "logo.svg"} {
		if !excl.ShouldExcludePath(shouldSkip) {
			t.Errorf("expected MakeCommonExclusions to exclude %q", shouldSkip)
		}
	}
	// Recall check: minified JS bundles MUST NOT be excluded by default (real API keys leak in bundles).
	if excl.ShouldExcludePath("dist/bundle.min.js") {
		t.Errorf("MakeCommonExclusions must NOT exclude dist/bundle.min.js by default")
	}

	// 7. v1.8.2 guards: benign domain keys (band_key, rate_key, plan_key), relative
	// document paths with ISO date ranges, newline-terminated dividers, and no
	// multi-line bleed across object properties into unrelated assignments.
	v182FP := `
const band = {
  band_key: 'starter-25',
  rate_key: 'ai_vision_pack_500',
  plan_key: 'growth_practice',
};
const samplePdf = 'samples/feed_export_2025-08-01-2026-07-31.pdf';
const sampleCsv = 'samples/feed_export_2025-08-01-2026-07-31.csv';
const sep = "------------------------------------------------------------\n";
const pricing = calc({
  moduleKeys: sub.modules,
  promo: sub.promo
});
const invNumber = ` + "`GB-INV-${year}-0007`" + `;
`
	for _, d := range scanInlineSnippet("pricing.ts", v182FP) {
		if d.Justification.Headline.Confidence >= diagnostics.High {
			t.Errorf("unexpected High+ FP in v1.8.2 guard snippet: provider=%v source=%q headline=%+v",
				d.ProviderID, d.GetValue(), d.Justification.Headline)
		}
	}

	// Recall check: a genuine vendor secret inside even a benign-named key MUST still be caught!
	leakedInBenignKey := `const band_key = "` + "sk_live_" + `4eC39HqLyjWDarjtT1zdp7dc";`
	foundReal := false
	for _, d := range scanInlineSnippet("leak.ts", leakedInBenignKey) {
		if d.Justification.Headline.Confidence >= diagnostics.Critical {
			foundReal = true
		}
	}
	if !foundReal {
		t.Errorf("real Stripe secret assigned to benign domain key must still be detected as Critical")
	}
}
