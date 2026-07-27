package sqlite

import (
	"testing"

	"github.com/adedayo/checkmate-core/pkg/projects"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewDB(t *testing.T) {
	tempDir := t.TempDir()

	db, err := New(tempDir)
	require.NoError(t, err, "Should create and initialize DB without error")
	require.NotNil(t, db)
	require.NotNil(t, db.db)

	require.Equal(t, tempDir, db.GetBaseDir())
	require.NotEmpty(t, db.GetCodeBaseDir())

	err = db.Close()
	require.NoError(t, err)
}

func TestDB_ProjectLifecycle(t *testing.T) {
	tempDir := t.TempDir()
	db, err := New(tempDir)
	require.NoError(t, err)
	defer db.Close()

	desc := projects.ProjectDescription{
		Name:      "Test Project",
		Workspace: "default",
	}

	// Create
	proj, err := db.CreateProject(desc)
	require.NoError(t, err)
	require.NotNil(t, proj)
	require.NotEmpty(t, proj.ID)
	require.Equal(t, "Test Project", proj.Name)

	// Get Project Summary
	summary, err := db.GetProjectSummary(proj.ID)
	require.NoError(t, err)
	require.NotNil(t, summary)
	require.Equal(t, proj.ID, summary.ID)
	require.Equal(t, "Test Project", summary.Name)

	// List Project Summaries
	summaries := db.ListProjectSummaries()
	require.Len(t, summaries, 1)
	assert.Equal(t, proj.ID, summaries[0].ID)

	// Update Project
	newDesc := projects.ProjectDescription{
		Name:      "Updated Project",
		Workspace: "default",
	}
	updatedProj, err := db.UpdateProject(proj.ID, newDesc, projects.SimpleWorkspaceSummariser)
	require.NoError(t, err)
	require.Equal(t, "Updated Project", updatedProj.Name)

	// Verify Update
	summary, err = db.GetProjectSummary(proj.ID)
	require.NoError(t, err)
	require.Equal(t, "Updated Project", summary.Name)

	// Delete Project
	err = db.DeleteProject(proj.ID)
	require.NoError(t, err)

	summaries = db.ListProjectSummaries()
	require.Empty(t, summaries)
}

func TestDB_Workspaces(t *testing.T) {
	tempDir := t.TempDir()
	db, err := New(tempDir)
	require.NoError(t, err)
	defer db.Close()

	desc := projects.ProjectDescription{
		Name:      "Proj 1",
		Workspace: "Test Workspace",
	}
	proj, err := db.CreateProject(desc)
	require.NoError(t, err)

	retrieved, err := db.GetWorkspaces()
	require.NoError(t, err)
	require.NotNil(t, retrieved)
	require.Contains(t, retrieved.Details, "Test Workspace")
	require.Len(t, retrieved.Details["Test Workspace"].ProjectSummaries, 1)
	assert.Equal(t, proj.ID, retrieved.Details["Test Workspace"].ProjectSummaries[0].ID)
}
