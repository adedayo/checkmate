package auth

import "time"

// APIKeyScope defines the allowed actions for an API Key
type APIKeyScope string

const (
	ScopeScanRead       APIKeyScope = "scan:read"
	ScopeScanWrite      APIKeyScope = "scan:write"
	ScopeExceptionRead  APIKeyScope = "exception:read"
	ScopeExceptionWrite APIKeyScope = "exception:write"
	ScopeAdmin          APIKeyScope = "admin"
)

// APIKey represents the metadata of an API key stored in CheckMate.
// The plaintext secret is never stored.
type APIKey struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	KeyPrefix   string        `json:"keyPrefix"`
	Scopes      []APIKeyScope `json:"scopes"`
	CreatedBy   string        `json:"createdBy"`
	CreatedAt   time.Time     `json:"createdAt"`
	ExpiresAt   *time.Time    `json:"expiresAt,omitempty"`
	LastUsedAt  *time.Time    `json:"lastUsedAt,omitempty"`
	IPAllowlist []string      `json:"ipAllowlist,omitempty"`
}

// APIKeyCreated represents the response when an API key is first generated.
// It includes the plaintext key which will never be retrievable again.
type APIKeyCreated struct {
	APIKey
	Key string `json:"key"`
}

// RefreshToken represents a stored refresh token for JWT sessions.
type RefreshToken struct {
	TokenHash string
	Username  string
	ExpiresAt time.Time
	CreatedAt time.Time
}

// Store defines the data access layer for Authentication primitives.
type Store interface {
	// API Keys
	CreateAPIKey(key *APIKey, hash string) error
	ListAPIKeys() ([]*APIKey, error)
	GetAPIKeyByPrefix(prefix string) (*APIKey, string, error) // Returns (APIKey, hash, error)
	DeleteAPIKey(id string) error

	// Refresh Tokens
	StoreRefreshToken(tokenHash, username string, expiresAt time.Time) error
	ValidateRefreshToken(tokenHash string) (string, error) // Returns username if valid
	RevokeRefreshToken(tokenHash string) error
}
