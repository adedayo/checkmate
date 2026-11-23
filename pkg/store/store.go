package store

import (
	"time"

	"github.com/adedayo/checkmate/pkg/core/diagnostics"
	"github.com/adedayo/checkmate/pkg/core/projects"
	"github.com/adedayo/checkmate/pkg/auth"
	"github.com/adedayo/checkmate/pkg/sdk"
)

// PlatformStore extends the core ProjectManager and Auth Store with new v1 platform capabilities.
// This interface decouples the API layer from any specific storage mechanism (e.g. SQLite).
type PlatformStore interface {
	projects.ProjectManager
	auth.Store

	// ListProjectScans returns paginated scans for a project, newest first.
	ListProjectScans(projectID string, limit, offset int) ([]*ScanRecord, error)

	// GetScanMetrics returns the metrics for a specific scan.
	GetScanMetrics(projectID, scanID string) (*ScanMetrics, error)
	
	// DeleteProjectScans removes all historical scans for a project.
	DeleteProjectScans(projectID string) error

	// SearchFindings searches findings across projects using dynamic filters.
	SearchFindings(req FindingSearchRequest) (*FindingSearchResult, error)

	// GetFinding returns a single finding by its finding_id.
	GetFinding(findingID string) (*sdk.Finding, error)

	// UpdateFindingAIAnnotation sets the AI annotation for a specific finding.
	UpdateFindingAIAnnotation(findingID string, annotation *sdk.AIAnnotation) error

	// Ping checks if the database connection is alive.
	Ping() error

	// GetBroker returns the active event broker for SSE pubsub.
	GetBroker() *ScanEventBroker

	// Phase 2: Exceptions
	CreateException(exc *Exception) error
	GetException(id string) (*Exception, error)
	ListExceptions(projectID string) ([]*Exception, error)
	UpdateException(id string, updates ExceptionUpdate) (*Exception, error)
	DeleteException(id string) error
	BuildExclusionProvider(projectID string) (diagnostics.ExclusionProvider, error)

	// Phase 2: Webhooks
	CreateWebhook(webhook *Webhook) error
	GetWebhooks() ([]*Webhook, error)
	DeleteWebhook(id string) error
	RecordWebhookDelivery(log *WebhookDeliveryLog) error
	SetWebhookDispatcher(dispatcher func(eventType string, data interface{}))

	// Phase 3: AI Settings
	GetAISettings() (*AISettings, error)
	UpdateAISettings(settings *AISettings) error
	GetUnannotatedFindings(scanID string) ([]string, error)
	GetAITokenUsage() (*AITokenUsage, error)

	// Agent MCP & Triage write-back
	GetScanProjectID(scanID string) (string, error)
	GetScanFileCount(scanID string) (int, error)
	GetScanFindings(scanID string) ([]*StoredFinding, error)
	UpdateFindingTriage(scanID, findingID string, update TriageUpdate) (int, error)
	RecomputeScanSummary(scanID string) (*SanitisedSummary, error)
	GetSanitisedSummary(scanID string) (*SanitisedSummary, error)
	PreviewExceptionOnScan(scanID string, exc *Exception) (*ExceptionPreview, error)
	ApplyExceptionToScan(scanID string, exc *Exception, triagedBy string, force bool) (*ExceptionApplyResult, error)
	RecordAuditEvent(audit *AuditEvent, resourceType, resourceID string) error
}

// StoredFinding is a full finding row retrieved from storage, including
// deterministic detection fields, suppression state, and triage metadata.
type StoredFinding struct {
	FindingID          string            `json:"findingId"`
	ScanID             string            `json:"scanId"`
	ProjectID          string            `json:"projectId,omitempty"`
	RuleID             string            `json:"ruleId"`
	SecretType         sdk.SecretType    `json:"secretType"`
	Severity           sdk.Severity      `json:"severity"`
	Confidence         sdk.Confidence    `json:"confidence"`
	RepositoryURL      string            `json:"repoUrl,omitempty"`
	CommitSHA          string            `json:"commitSha,omitempty"`
	Branch             string            `json:"branch,omitempty"`
	File               string            `json:"file"`
	Line               int               `json:"line"`
	Column             int               `json:"column"`
	EndLine            int               `json:"endLine,omitempty"`
	EndColumn          int               `json:"endColumn,omitempty"`
	EvidenceRedacted   string            `json:"evidenceRedacted,omitempty"`
	SecretChecksum     string            `json:"secretChecksum"`
	SourceContext      string            `json:"sourceContext,omitempty"`
	Suppressed         bool              `json:"suppressed"`
	ExceptionID        string            `json:"exceptionId,omitempty"`
	VerificationStatus string            `json:"verificationStatus"`
	AIAnnotation       *sdk.AIAnnotation `json:"aiAnnotation,omitempty"`
	TriageStatus       sdk.TriageStatus  `json:"triageStatus"`
	TriageSource       string            `json:"triageSource,omitempty"`
	TriagedAt          *time.Time        `json:"triagedAt,omitempty"`
	ContextHash        string            `json:"contextHash,omitempty"`
	DetectedAt         time.Time         `json:"detectedAt"`
}

// TriageUpdate describes an agent or human triage decision persisted for a finding.
type TriageUpdate struct {
	Status              sdk.TriageStatus  `json:"status"`
	Source              string            `json:"source"`
	Annotation          *sdk.AIAnnotation `json:"annotation,omitempty"`
	Suppressed          *bool             `json:"suppressed,omitempty"`
	ExceptionID         string            `json:"exceptionId,omitempty"`
	ApplyToSameChecksum bool              `json:"applyToSameChecksum,omitempty"`
}

// SanitisedSummary holds post-triage, post-suppression metrics for a scan
// alongside raw totals without mutating deterministic scan columns.
type SanitisedSummary struct {
	RawFindings              int            `json:"rawFindings"`
	ActiveFindings           int            `json:"activeFindings"`
	SuppressedFindings       int            `json:"suppressedFindings"`
	TriagedTruePositives     int            `json:"triagedTruePositives"`
	TriagedFalsePositives    int            `json:"triagedFalsePositives"`
	NeedsReview              int            `json:"needsReview"`
	Untriaged                int            `json:"untriaged"`
	ActiveFindingsBySeverity map[string]int `json:"activeFindingsBySeverity"`
	SanitisedScore           float64        `json:"sanitisedScore"`
	NoiseReductionPercent    float64        `json:"noiseReductionPercent"`
	LastTriagedAt            *time.Time     `json:"lastTriagedAt,omitempty"`
	LastTriagedBy            string         `json:"lastTriagedBy,omitempty"`
}

// ExceptionPreview describes the blast radius of a candidate exception rule on a scan.
type ExceptionPreview struct {
	MatchedCount               int                      `json:"matchedCount"`
	UntriagedMatchedCount      int                      `json:"untriagedMatchedCount"`
	AlreadySuppressedCount     int                      `json:"alreadySuppressedCount"`
	WouldSuppressTruePositives int                      `json:"wouldSuppressTruePositives"`
	ConflictingFindingIDs      []string                 `json:"conflictingFindingIds,omitempty"`
	MatchedByRule              map[string]int           `json:"matchedByRule"`
	SampleMatchedLocations     []ExceptionMatchLocation `json:"sampleMatchedLocations"`
}

// ExceptionMatchLocation identifies a finding matched by a candidate exception rule.
type ExceptionMatchLocation struct {
	FindingID    string           `json:"findingId"`
	File         string           `json:"file"`
	Line         int              `json:"line"`
	Column       int              `json:"column"`
	RuleID       string           `json:"ruleId"`
	TriageStatus sdk.TriageStatus `json:"triageStatus"`
	Suppressed   bool             `json:"suppressed"`
}

// ExceptionApplyResult summarises applying an exception rule to a scan.
type ExceptionApplyResult struct {
	ExceptionID        string            `json:"exceptionId"`
	SuppressedCount    int               `json:"suppressedCount"`
	AlreadySuppressed  int               `json:"alreadySuppressed"`
	SanitisedSummary   *SanitisedSummary `json:"sanitisedSummary"`
}

// AITokenUsage aggregates the cost of AI triage
type AITokenUsage struct {
	PromptTokens     int `json:"promptTokens"`
	CompletionTokens int `json:"completionTokens"`
}

// AISettings represents the Bring-Your-Own-Key AI configuration
type AISettings struct {
	Enabled           bool   `json:"enabled"`
	Provider          string `json:"provider"`
	Model             string `json:"model"`
	BaseURL           string `json:"baseUrl"`
	APIKey            string `json:"apiKey"`
	DefaultPromptMode string `json:"defaultPromptMode"`
}

// ScanRecord represents a scan execution in the database.
type ScanRecord struct {
	ID          string     `json:"id"`
	ProjectID   string     `json:"projectId,omitempty"`
	Status      string     `json:"status"`
	StartedAt   time.Time  `json:"startedAt"`
	CompletedAt *time.Time `json:"completedAt,omitempty"`
}

// ScanMetrics holds summary information about findings from a scan.
type ScanMetrics struct {
	TotalFindings      int            `json:"totalFindings"`
	FindingsBySeverity map[string]int `json:"findingsBySeverity"`
	Score              float64        `json:"score"`
}

// FindingSearchRequest defines the criteria for searching findings.
type FindingSearchRequest struct {
	ProjectIDs  []string
	Severity    []sdk.Severity
	SecretTypes []sdk.SecretType
	Suppressed  *bool
	Page        int
	Limit       int
}

// FindingSearchResult holds paginated finding results.
type FindingSearchResult struct {
	Findings   []*diagnostics.SecurityDiagnostic
	TotalCount int
	Page       int
	Limit      int
}

// Exception models a suppression rule.
type Exception struct {
	ID            string                `json:"id"`
	ProjectID     string                `json:"projectId,omitempty"`
	RuleID        string                `json:"ruleId"`
	Scope         *ExceptionScopeDetail `json:"scope"`
	Reason        string                `json:"reason"`
	Justification string                `json:"justification,omitempty"`
	CreatedBy     string                `json:"createdBy"`
	CreatedAt     time.Time             `json:"createdAt"`
	ExpiresAt     *time.Time            `json:"expiresAt,omitempty"`
	Status        string                `json:"status"`
	Evidence      *ExceptionEvidence    `json:"evidence,omitempty"`
	Tags          []string              `json:"tags,omitempty"`
	AuditTrail    []*AuditEvent         `json:"auditTrail,omitempty"`
}

type ExceptionScopeDetail struct {
	Type           string `json:"type"` // e.g. "globalHash", "globalString", "globalRegex", "pathRegex", "pathHash", "pathString"
	RepoURL        string `json:"repoUrl,omitempty"`
	Path           string `json:"path,omitempty"`
	LineStart      *int   `json:"lineStart,omitempty"`
	LineEnd        *int   `json:"lineEnd,omitempty"`
	SecretChecksum string `json:"secretChecksum,omitempty"`
	StringMatch    string `json:"stringMatch,omitempty"`
	RegexMatch     string `json:"regexMatch,omitempty"`
}

type ExceptionEvidence struct {
	FileHash  string `json:"fileHash,omitempty"`
	CommitSha string `json:"commitSha,omitempty"`
}

type AuditEvent struct {
	Action    string    `json:"action"`
	Timestamp time.Time `json:"timestamp"`
	User      string    `json:"user"`
	Details   string    `json:"details,omitempty"`
}

type ExceptionUpdate struct {
	ExpiresAt     *time.Time `json:"expiresAt,omitempty"`
	Justification *string    `json:"justification,omitempty"`
	Tags          []string   `json:"tags,omitempty"`
}

// Webhook models a push notification configuration.
type Webhook struct {
	ID        string    `json:"id"`
	URL       string    `json:"url"`
	Events    []string  `json:"events"`
	CreatedAt time.Time `json:"createdAt"`
	Secret    string    `json:"secret,omitempty"`
}

// WebhookDeliveryLog tracks a delivery attempt
type WebhookDeliveryLog struct {
	ID            string    `json:"id"`
	WebhookID     string    `json:"webhookId"`
	EventType     string    `json:"eventType"`
	AttemptNumber int       `json:"attemptNumber"`
	ResponseCode  *int      `json:"responseCode,omitempty"`
	LatencyMs     *int      `json:"latencyMs,omitempty"`
	ErrorMessage  *string   `json:"errorMessage,omitempty"`
	CreatedAt     time.Time `json:"createdAt"`
}
