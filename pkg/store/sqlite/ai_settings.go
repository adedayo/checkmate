package sqlite

import (
	"database/sql"

	"github.com/adedayo/checkmate/pkg/store"
)

func (s *DB) GetAISettings() (*store.AISettings, error) {
	row := s.db.QueryRow(`
		SELECT enabled, provider, model, base_url, api_key, default_prompt_mode
		FROM ai_settings
		WHERE id = 1
	`)

	var settings store.AISettings
	var apiKey sql.NullString

	err := row.Scan(
		&settings.Enabled,
		&settings.Provider,
		&settings.Model,
		&settings.BaseURL,
		&apiKey,
		&settings.DefaultPromptMode,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			// Should theoretically never happen due to INSERT OR IGNORE, but return safe defaults
			return &store.AISettings{
				Enabled:           false,
				Provider:          "ollama",
				Model:             "llama3",
				BaseURL:           "http://localhost:11434/v1",
				DefaultPromptMode: "REDACTED",
			}, nil
		}
		return nil, err
	}

	if apiKey.Valid {
		settings.APIKey = apiKey.String
	}

	return &settings, nil
}

func (s *DB) UpdateAISettings(settings *store.AISettings) error {
	var apiKey interface{}
	if settings.APIKey == "" {
		apiKey = nil
	} else {
		apiKey = settings.APIKey
	}

	_, err := s.db.Exec(`
		UPDATE ai_settings
		SET enabled = ?, provider = ?, model = ?, base_url = ?, api_key = ?, default_prompt_mode = ?
		WHERE id = 1
	`,
		settings.Enabled,
		settings.Provider,
		settings.Model,
		settings.BaseURL,
		apiKey,
		settings.DefaultPromptMode,
	)

	return err
}
