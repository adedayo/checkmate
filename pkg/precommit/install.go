package precommit

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const ManagedHookMarker = "# checkmate-managed-hook"

const hookScriptTemplate = `#!/bin/sh
` + ManagedHookMarker + `
# Installed by: checkmate hook install
# Remove with:  checkmate hook uninstall

if ! command -v checkmate >/dev/null 2>&1; then
  echo "CheckMate pre-commit hook: 'checkmate' binary not found in PATH." >&2
  exit 2
fi

exec checkmate hook run --staged "$@"
`

// ResolveHookPath returns the filesystem path of the repository's pre-commit
// hook, honouring worktrees and custom core.hooksPath settings.
func ResolveHookPath(ctx context.Context, dir string) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	repoRoot, err := RepoRoot(ctx, dir)
	if err != nil {
		return "", err
	}

	cmd := exec.CommandContext(ctx, "git", "rev-parse", "--git-path", "hooks/pre-commit")
	cmd.Dir = repoRoot
	out, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && len(exitErr.Stderr) > 0 {
			return "", fmt.Errorf("failed to resolve git hook path: %s", strings.TrimSpace(string(exitErr.Stderr)))
		}
		return "", fmt.Errorf("failed to resolve git hook path: %w", err)
	}

	hookPath := strings.TrimSpace(string(out))
	if !filepath.IsAbs(hookPath) {
		hookPath = filepath.Join(repoRoot, hookPath)
	}
	return filepath.Clean(hookPath), nil
}

// InstallHook installs the CheckMate pre-commit hook script. If a non-CheckMate
// hook already exists and force is false, an error is returned.
func InstallHook(ctx context.Context, dir string, force bool) (string, error) {
	hookPath, err := ResolveHookPath(ctx, dir)
	if err != nil {
		return "", err
	}

	if existing, err := os.ReadFile(hookPath); err == nil {
		if !force && !strings.Contains(string(existing), ManagedHookMarker) {
			return "", fmt.Errorf("pre-commit hook already exists at %s and is not managed by CheckMate (pass --force to overwrite)", hookPath)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("failed checking existing hook at %s: %w", hookPath, err)
	}

	if err := os.MkdirAll(filepath.Dir(hookPath), 0o755); err != nil {
		return "", fmt.Errorf("failed creating hooks directory: %w", err)
	}
	if err := os.WriteFile(hookPath, []byte(hookScriptTemplate), 0o755); err != nil {
		return "", fmt.Errorf("failed writing hook script at %s: %w", hookPath, err)
	}
	return hookPath, nil
}

// UninstallHook removes a CheckMate-managed pre-commit hook. Refuses to remove
// hooks that do not carry ManagedHookMarker.
func UninstallHook(ctx context.Context, dir string) (string, error) {
	hookPath, err := ResolveHookPath(ctx, dir)
	if err != nil {
		return "", err
	}

	existing, err := os.ReadFile(hookPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", fmt.Errorf("no pre-commit hook found at %s", hookPath)
		}
		return "", fmt.Errorf("failed reading hook at %s: %w", hookPath, err)
	}
	if !strings.Contains(string(existing), ManagedHookMarker) {
		return "", fmt.Errorf("refusing to remove %s: hook is not managed by CheckMate", hookPath)
	}
	if err := os.Remove(hookPath); err != nil {
		return "", fmt.Errorf("failed removing hook at %s: %w", hookPath, err)
	}
	return hookPath, nil
}
