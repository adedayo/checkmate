package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"

	gitutils "github.com/adedayo/checkmate-core/pkg/git"
)

// gitConfigManager wraps the DB to implement gitutils.GitConfigManager.
type gitConfigManager struct {
	db *DB
}

func newGitConfigManager(db *DB) *gitConfigManager {
	return &gitConfigManager{db: db}
}

// GetConfig retrieves the stored GitServiceConfig.
func (g *gitConfigManager) GetConfig() (*gitutils.GitServiceConfig, error) {
	g.db.mu.RLock()
	defer g.db.mu.RUnlock()

	var dataJSON string
	err := g.db.db.QueryRowContext(context.Background(),
		`SELECT data FROM git_config WHERE id = 'singleton'`).Scan(&dataJSON)
	if err == sql.ErrNoRows {
		// No config yet — return empty
		return &gitutils.GitServiceConfig{
			GitServices: make(map[gitutils.GitServiceType]map[string]*gitutils.GitService),
		}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get git config: %w", err)
	}

	var cfg gitutils.GitServiceConfig
	if err := json.Unmarshal([]byte(dataJSON), &cfg); err != nil {
		return nil, fmt.Errorf("unmarshal git config: %w", err)
	}
	return &cfg, nil
}

// SaveConfig persists the GitServiceConfig.
func (g *gitConfigManager) SaveConfig(cfg *gitutils.GitServiceConfig) error {
	if cfg == nil {
		return nil
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal git config: %w", err)
	}

	g.db.mu.Lock()
	defer g.db.mu.Unlock()

	_, err = g.db.db.ExecContext(context.Background(), `
		INSERT INTO git_config(id, data) VALUES ('singleton', ?)
		ON CONFLICT(id) DO UPDATE SET data = excluded.data`,
		string(data))
	if err != nil {
		log.Printf("SaveConfig: %v", err)
	}
	return err
}
