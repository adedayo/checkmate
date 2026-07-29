package sqlite

import (
	"testing"
	"time"

	"github.com/adedayo/checkmate/pkg/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDB_Webhooks(t *testing.T) {
	tempDir := t.TempDir()
	db, err := New(tempDir)
	require.NoError(t, err)
	defer func() {
		_ = db.Close()
	}()

	webhook := &store.Webhook{
		ID:        "wh_123",
		URL:       "https://example.com/webhook",
		Events:    []string{"scan.completed"},
		CreatedAt: time.Now(),
		Secret:    "supersecret",
	}

	err = db.CreateWebhook(webhook)
	require.NoError(t, err)

	list, err := db.GetWebhooks()
	require.NoError(t, err)
	require.Len(t, list, 1)

	fetched := list[0]
	assert.Equal(t, "wh_123", fetched.ID)
	assert.Equal(t, "https://example.com/webhook", fetched.URL)
	assert.Equal(t, []string{"scan.completed"}, fetched.Events)
	// Secret is hashed and not returned by GetWebhooks
	assert.Equal(t, "", fetched.Secret)

	err = db.DeleteWebhook("wh_123")
	require.NoError(t, err)

	listAfterDelete, err := db.GetWebhooks()
	require.NoError(t, err)
	assert.Len(t, listAfterDelete, 0)
}
