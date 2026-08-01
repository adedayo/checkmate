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
