package store

import (
	"time"

	"github.com/adedayo/checkmate-core/pkg/diagnostics"
	"github.com/adedayo/checkmate-core/pkg/projects"
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
	ListExceptions() ([]*Exception, error)
	UpdateException(id string, updates ExceptionUpdate) (*Exception, error)
	DeleteException(id string) error

	// Phase 2: Webhooks
	CreateWebhook(webhook *Webhook) error
	GetWebhooks() ([]*Webhook, error)
	DeleteWebhook(id string) error

	// Phase 3: AI Settings
	GetAISettings() (*AISettings, error)
	UpdateAISettings(settings *AISettings) error
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
	Type           string `json:"type"`
	RepoURL        string `json:"repoUrl,omitempty"`
	Path           string `json:"path,omitempty"`
	LineStart      *int   `json:"lineStart,omitempty"`
	LineEnd        *int   `json:"lineEnd,omitempty"`
	SecretChecksum string `json:"secretChecksum,omitempty"`
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
