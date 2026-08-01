package sdk

import "time"

// SecretType is a structured taxonomy of secret types that CheckMate can detect.
// It replaces the previous opaque rule-name strings.
type SecretType string

const (
	// Cloud providers
	SecretTypeAWSAccessKey    SecretType = "aws.access_key"
	SecretTypeAWSSecretKey    SecretType = "aws.secret_key"
	SecretTypeAWSSessionToken SecretType = "aws.session_token"
	SecretTypeGCPServiceAcct  SecretType = "gcp.service_account_key"
	SecretTypeAzureClientSec  SecretType = "azure.client_secret"
	SecretTypeAzureSASToken   SecretType = "azure.sas_token"

	// Source control platforms
	SecretTypeGitHubPAT       SecretType = "github.personal_access_token"
	SecretTypeGitHubFineGrain SecretType = "github.fine_grained_token"
	SecretTypeGitHubAppKey    SecretType = "github.app_private_key"
	SecretTypeGitLabPAT       SecretType = "gitlab.personal_access_token"

	// Databases
	SecretTypeDBPassword       SecretType = "db.password"
	SecretTypeConnectionString SecretType = "db.connection_string"

	// Cryptographic material
	SecretTypeRSAPrivateKey SecretType = "crypto.rsa_private_key"
	SecretTypeECPrivateKey  SecretType = "crypto.ec_private_key"
	SecretTypePKCS12        SecretType = "crypto.pkcs12"
	SecretTypePEMPrivateKey SecretType = "crypto.pem_private_key"
	SecretTypeSSHPrivateKey SecretType = "crypto.ssh_private_key"

	// Generic / fallback patterns
	SecretTypeHighEntropy SecretType = "generic.high_entropy"
	SecretTypePassword    SecretType = "generic.password"
	SecretTypeAPIKey      SecretType = "generic.api_key"
	SecretTypeToken       SecretType = "generic.token"
	SecretTypeJWT         SecretType = "generic.jwt"
)

// Severity represents how critical a finding is.
// Computed deterministically from SecretType + Confidence + VerificationStatus.
// Never overridden by AI triage.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// Confidence represents how confident CheckMate is that this is a real secret.
type Confidence string

const (
	ConfidenceConfirmed Confidence = "CONFIRMED"
	ConfidenceHigh      Confidence = "HIGH"
	ConfidenceMedium    Confidence = "MEDIUM"
	ConfidenceLow       Confidence = "LOW"
)

// VerificationStatus represents the result of optional live verification
// against the issuing provider. Default is NOT_CHECKED (live verification
// is a deferred feature).
type VerificationStatus string

const (
	VerificationNotChecked VerificationStatus = "NOT_CHECKED"
	VerificationActive     VerificationStatus = "ACTIVE"
	VerificationRevoked    VerificationStatus = "REVOKED"
	VerificationUnknown    VerificationStatus = "UNKNOWN"
)

// Finding is a detected secret. The raw secret value is never stored in this
// struct — only the checksum and a redacted display form.
//
// The ID is a deterministic stable identifier:
//
//	sha256(RuleID + RepositoryURL + File + Line + Column + SecretChecksum)
//
// The same physical secret across different scans always produces the same ID.
type Finding struct {
	// Stable deterministic identity
	ID string

	// Detection metadata
	RuleID     string
	SecretType SecretType
	Severity   Severity
	Confidence Confidence

	// Location
	RepositoryURL string // empty for filesystem scans
	CommitSHA     string // empty for filesystem scans
	Branch        string
	File          string
	Line          int
	Column        int

	// Evidence — raw value is NEVER stored here
	// EvidenceRedacted shows first 4 + last 4 characters only
	EvidenceRedacted string
	// SecretChecksum is sha256 of the raw secret value, for dedup and exception matching
	SecretChecksum string

	// SourceContext is the surrounding code with the secret position replaced by ████.
	// Suitable for display in UIs and AI triage prompts.
	SourceContext string

	// Exception tracking
	Suppressed  bool
	ExceptionID string // empty if not suppressed

	// Verification — deferred feature, always NOT_CHECKED until implemented
	VerificationStatus VerificationStatus
	VerifiedAt         *time.Time

	// AI triage — nil until triage is run for this finding
	AIAnnotation *AIAnnotation

	DetectedAt time.Time
}

// AIAnnotation holds the output of AI triage for a finding.
// INVARIANT: AIAnnotation NEVER modifies Finding.Severity or Finding.Confidence.
// Those fields remain pure functions of SecretType + Confidence + VerificationStatus.
// AIAnnotation is display-only — it annotates, it does not score.
type AIAnnotation struct {
	Model    string
	Provider string
	// PromptMode records whether the raw secret value was included in the prompt.
	// RAW_VALUE is only ever used when the AI provider is a verified local endpoint.
	PromptMode PromptMode

	// FPLikelihood is the model's estimated probability (0.0–1.0) that this
	// finding is a false positive.
	FPLikelihood float64

	Summary         string
	RemediationHint string
	ContextClues    []string

	GeneratedAt      time.Time
	PromptTokens     int
	CompletionTokens int

	UserOverridden bool   `json:"userOverridden,omitempty"`
	UserDecision   string `json:"userDecision,omitempty"` // "true_positive" or "false_positive"
}

// PromptMode records what was sent to the AI model about the detected secret.
type PromptMode string

const (
	// PromptModeRedacted sends only redacted context — safe for any provider.
	// This is always the default.
	PromptModeRedacted PromptMode = "REDACTED"

	// PromptModeRawValue sends the actual secret value in addition to context.
	// Only active when CHECKMATE_AI_ALLOW_RAW_VALUE=true AND the configured
	// AI base URL resolves to a private/loopback address. Cloud endpoints are
	// always silently downgraded to REDACTED regardless of the flag.
	PromptModeRawValue PromptMode = "RAW_VALUE"
)

// Options configures the scanner behaviour.
type Options struct {
	// ShowSource includes surrounding source code context in findings.
	ShowSource bool

	// CalculateChecksum computes sha256 of detected secrets (for dedup).
	CalculateChecksum bool

	// ExcludeTestFiles skips test files during scanning.
	ExcludeTestFiles bool

	// SensitiveFilesOnly limits scanning to known sensitive file types
	// (certificates, keystores, etc.) — no content scanning.
	SensitiveFilesOnly bool

	// ExclusionFile is an optional path to a .checkmate.yaml exception policy.
	ExclusionFile string

	// ExcludePatterns is a list of glob patterns to exclude from scanning.
	ExcludePatterns []string
}

// DefaultOptions returns the recommended defaults for most use cases.
func DefaultOptions() Options {
	return Options{
		ShowSource:        true,
		CalculateChecksum: true,
	}
}

// ScanProgress is emitted during streaming scans to report progress.
type ScanProgress struct {
	CurrentFile  string
	FilesScanned int
	// TotalFiles may be 0 if not known in advance (e.g. large git history)
	TotalFiles int
}
