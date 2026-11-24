package precommit

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/adedayo/checkmate/pkg/core/diagnostics"
	"github.com/adedayo/checkmate/pkg/core/projects"
	secrets "github.com/adedayo/checkmate/pkg/plugin/secrets-finder/pkg"
	"github.com/adedayo/checkmate/pkg/store"
	homedir "github.com/mitchellh/go-homedir"
	"gopkg.in/yaml.v3"
	_ "modernc.org/sqlite"
)

const WorkspaceExclusionFile = ".checkmate.yaml"

// ExclusionOptions configures how CLI/pre-commit exclusions are loaded.
type ExclusionOptions struct {
	// RepoRoot is the repository or working directory root used for
	// auto-discovering .checkmate.yaml and matching SQLite project scopes.
	RepoRoot string
	// ExplicitFile is an optional user-supplied exclusion YAML path (-e).
	// Missing or malformed explicit files return an error (fail closed).
	ExplicitFile string
	// AutoDiscover loads <RepoRoot>/.checkmate.yaml when present.
	AutoDiscover bool
	// DataPath is the CheckMate data directory (default ~/.checkmate) where
	// checkmate.db may reside for shared SQLite exceptions.
	DataPath string
	// NoDB disables reading active exceptions from SQLite.
	NoDB bool
	// Repositories lists directory roots stripped when matching relative
	// PerFileExcludedStrings/PerFileExcludedHashes entries.
	Repositories []string
}

// LoadExclusions builds a compiled ExclusionProvider merging built-in common
// exclusions, optional repo-root .checkmate.yaml, optional explicit YAML, and
// optional read-only SQLite active exceptions.
func LoadExclusions(opts ExclusionOptions) (diagnostics.ExclusionProvider, error) {
	def := secrets.MakeCommonExclusions()
	ensureDefMaps(&def)

	root := strings.TrimSpace(opts.RepoRoot)
	if root != "" {
		if abs, err := filepath.Abs(root); err == nil {
			root = abs
		}
	}

	if opts.AutoDiscover && root != "" {
		wsFile := filepath.Join(root, WorkspaceExclusionFile)
		if info, err := os.Stat(wsFile); err == nil && !info.IsDir() {
			parsed, err := readExclusionYAML(wsFile)
			if err != nil {
				return nil, fmt.Errorf("failed to load %s: %w", wsFile, err)
			}
			def = secrets.MergeExclusions(parsed, def)
			ensureDefMaps(&def)
		}
	}

	if strings.TrimSpace(opts.ExplicitFile) != "" {
		parsed, err := readExclusionYAML(opts.ExplicitFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load exclusion file %s: %w", opts.ExplicitFile, err)
		}
		def = secrets.MergeExclusions(parsed, def)
		ensureDefMaps(&def)
	}

	if !opts.NoDB {
		dataPath := strings.TrimSpace(opts.DataPath)
		if dataPath == "" {
			dataPath = "~/.checkmate"
		}
		if expanded, err := homedir.Expand(dataPath); err == nil {
			dbPath := filepath.Join(expanded, "checkmate.db")
			if info, err := os.Stat(dbPath); err == nil && !info.IsDir() {
				_ = mergeReadOnlySQLiteExceptions(dbPath, root, &def)
			}
		}
	}

	repos := directoryRootsOnly(opts.Repositories)
	if root != "" {
		repos = appendUniqueStr(repos, root)
	}

	compiled, err := diagnostics.CompileExcludes(diagnostics.ExcludeContainer{
		ExcludeDef:   &def,
		Repositories: repos,
	})
	if err != nil {
		return nil, fmt.Errorf("invalid exclusion regex: %w", err)
	}
	return compiled, nil
}

func readExclusionYAML(path string) (diagnostics.ExcludeDefinition, error) {
	var parsed diagnostics.ExcludeDefinition
	data, err := os.ReadFile(path)
	if err != nil {
		return parsed, err
	}
	if err := yaml.Unmarshal(data, &parsed); err != nil {
		return parsed, err
	}
	return parsed, nil
}

func ensureDefMaps(def *diagnostics.ExcludeDefinition) {
	if def.PerFileExcludedStrings == nil {
		def.PerFileExcludedStrings = make(map[string][]string)
	}
	if def.PerFileExcludedHashes == nil {
		def.PerFileExcludedHashes = make(map[string][]string)
	}
	if def.PathRegexExcludedRegExs == nil {
		def.PathRegexExcludedRegExs = make(map[string][]string)
	}
}

// directoryRootsOnly filters candidate repository roots down to existing
// directories so individual file paths passed to the CLI are never used as
// stripping prefixes.
func directoryRootsOnly(paths []string) []string {
	var dirs []string
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if info, err := os.Stat(p); err == nil && info.IsDir() {
			dirs = appendUniqueStr(dirs, p)
		}
	}
	return dirs
}

// mergeReadOnlySQLiteExceptions opens checkmate.db in strict read-only mode
// without running schema migrations or creating files, and merges active
// global and workspace-matching project exceptions into def.
func mergeReadOnlySQLiteExceptions(dbPath, repoRoot string, def *diagnostics.ExcludeDefinition) error {
	dsn := fmt.Sprintf("file:%s?mode=ro&_pragma=busy_timeout(1000)", filepath.ToSlash(dbPath))
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()

	projectIDs := []string{""}
	if repoRoot != "" {
		if matched := findMatchingSQLiteProjects(db, repoRoot); len(matched) > 0 {
			projectIDs = append(projectIDs, matched...)
		}
	}

	placeholders := make([]string, len(projectIDs))
	args := make([]any, len(projectIDs))
	for i, pid := range projectIDs {
		placeholders[i] = "?"
		args[i] = pid
	}

	query := fmt.Sprintf(
		`SELECT scope_json, expires_at FROM exceptions WHERE status = 'active' AND project_id IN (%s)`,
		strings.Join(placeholders, ","),
	)
	rows, err := db.Query(query, args...)
	if err != nil {
		// Older DBs before migration 005 lack project_id; fall back safely.
		rows, err = db.Query(`SELECT scope_json, expires_at FROM exceptions WHERE status = 'active'`)
		if err != nil {
			return err
		}
	}
	defer func() { _ = rows.Close() }()

	now := time.Now().UTC()
	for rows.Next() {
		var scopeJSON string
		var expiresAt sql.NullString
		if err := rows.Scan(&scopeJSON, &expiresAt); err != nil {
			continue
		}
		if expiresAt.Valid && expiresAt.String != "" {
			if t, err := time.Parse(time.RFC3339, expiresAt.String); err == nil && !t.After(now) {
				continue
			}
		}
		var sc store.ExceptionScopeDetail
		if err := json.Unmarshal([]byte(scopeJSON), &sc); err != nil {
			continue
		}
		applyScopeToDef(&sc, repoRoot, def)
	}
	return nil
}

func findMatchingSQLiteProjects(db *sql.DB, repoRoot string) []string {
	rows, err := db.Query(`SELECT id, data FROM projects`)
	if err != nil {
		return nil
	}
	defer func() { _ = rows.Close() }()

	var ids []string
	for rows.Next() {
		var id, data string
		if err := rows.Scan(&id, &data); err != nil {
			continue
		}
		var proj projects.Project
		if err := json.Unmarshal([]byte(data), &proj); err != nil {
			continue
		}
		for _, repo := range proj.Repositories {
			loc := strings.TrimSpace(repo.Location)
			if loc == "" {
				continue
			}
			if abs, err := filepath.Abs(loc); err == nil {
				loc = abs
			}
			if sameOrNestedPath(loc, repoRoot) || sameOrNestedPath(repoRoot, loc) {
				ids = append(ids, id)
				break
			}
		}
	}
	return ids
}

func sameOrNestedPath(child, parent string) bool {
	c := filepath.Clean(child)
	p := filepath.Clean(parent)
	if c == p {
		return true
	}
	rel, err := filepath.Rel(p, c)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) && !filepath.IsAbs(rel)
}

func applyScopeToDef(sc *store.ExceptionScopeDetail, repoRoot string, def *diagnostics.ExcludeDefinition) {
	pathVariants := func(p string) []string {
		variants := []string{p}
		if repoRoot != "" {
			if trimmed := strings.TrimPrefix(p, repoRoot); trimmed != p {
				variants = appendUniqueStr(variants, trimmed)
				variants = appendUniqueStr(variants, strings.TrimPrefix(trimmed, string(os.PathSeparator)))
			}
		}
		return variants
	}

	switch sc.Type {
	case "globalHash", "value":
		if sc.SecretChecksum != "" {
			def.GloballyExcludedHashes = appendUniqueStr(def.GloballyExcludedHashes, sc.SecretChecksum)
		}
	case "globalString":
		if sc.StringMatch != "" {
			def.GloballyExcludedStrings = appendUniqueStr(def.GloballyExcludedStrings, sc.StringMatch)
		}
	case "globalRegex":
		if sc.RegexMatch != "" {
			def.GloballyExcludedRegExs = appendUniqueStr(def.GloballyExcludedRegExs, sc.RegexMatch)
		}
	case "pathRegex":
		if sc.RegexMatch != "" {
			def.PathExclusionRegExs = appendUniqueStr(def.PathExclusionRegExs, sc.RegexMatch)
		}
	case "pathString":
		if sc.Path != "" && sc.StringMatch != "" {
			for _, pv := range pathVariants(sc.Path) {
				def.PerFileExcludedStrings[pv] = appendUniqueStr(def.PerFileExcludedStrings[pv], sc.StringMatch)
			}
		}
	case "pathHash":
		if sc.Path != "" && sc.SecretChecksum != "" {
			for _, pv := range pathVariants(sc.Path) {
				def.PerFileExcludedHashes[pv] = appendUniqueStr(def.PerFileExcludedHashes[pv], sc.SecretChecksum)
			}
		}
	case "pathRegexRegex":
		if sc.Path != "" && sc.RegexMatch != "" {
			def.PathRegexExcludedRegExs[sc.Path] = appendUniqueStr(def.PathRegexExcludedRegExs[sc.Path], sc.RegexMatch)
		}
	}
}

func appendUniqueStr(slice []string, val string) []string {
	for _, s := range slice {
		if s == val {
			return slice
		}
	}
	return append(slice, val)
}
