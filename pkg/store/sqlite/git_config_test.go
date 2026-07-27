package sqlite

import (
	"testing"

	gitutils "github.com/adedayo/checkmate-core/pkg/git"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGitConfigManager_Empty(t *testing.T) {
	tempDir := t.TempDir()
	db, err := New(tempDir)
	require.NoError(t, err)
	defer db.Close()

	mgr := newGitConfigManager(db)

	cfg, err := mgr.GetConfig()
	require.NoError(t, err)
	require.NotNil(t, cfg)
	require.NotNil(t, cfg.GitServices)
	require.Empty(t, cfg.GitServices)
}

func TestGitConfigManager_SaveAndGet(t *testing.T) {
	tempDir := t.TempDir()
	db, err := New(tempDir)
	require.NoError(t, err)
	defer db.Close()

	mgr := newGitConfigManager(db)

	cfg := &gitutils.GitServiceConfig{
		GitServices: map[gitutils.GitServiceType]map[string]*gitutils.GitService{
			gitutils.GitHub: {
				"github.com": &gitutils.GitService{
					InstanceURL: "https://github.com",
				},
			},
		},
	}

	err = mgr.SaveConfig(cfg)
	require.NoError(t, err)

	retrieved, err := mgr.GetConfig()
	require.NoError(t, err)
	require.NotNil(t, retrieved)
	require.Contains(t, retrieved.GitServices, gitutils.GitHub)
	require.Contains(t, retrieved.GitServices[gitutils.GitHub], "github.com")
	assert.Equal(t, "https://github.com", retrieved.GitServices[gitutils.GitHub]["github.com"].InstanceURL)
}

func TestGitConfigManager_Update(t *testing.T) {
	tempDir := t.TempDir()
	db, err := New(tempDir)
	require.NoError(t, err)
	defer db.Close()

	mgr := newGitConfigManager(db)

	cfg := &gitutils.GitServiceConfig{
		GitServices: map[gitutils.GitServiceType]map[string]*gitutils.GitService{
			gitutils.GitHub: {
				"github.com": &gitutils.GitService{
					InstanceURL: "https://github.com",
				},
			},
		},
	}
	require.NoError(t, mgr.SaveConfig(cfg))

	// Update by modifying cfg
	cfg.GitServices[gitutils.GitLab] = map[string]*gitutils.GitService{
		"gitlab.com": &gitutils.GitService{
			InstanceURL: "https://gitlab.com",
		},
	}

	require.NoError(t, mgr.SaveConfig(cfg))

	retrieved, err := mgr.GetConfig()
	require.NoError(t, err)
	t.Logf("Retrieved services: %+v", retrieved.GitServices)
	require.Contains(t, retrieved.GitServices, gitutils.GitHub)
	require.Contains(t, retrieved.GitServices, gitutils.GitLab)
}
