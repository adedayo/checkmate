package lsp

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/adedayo/checkmate/pkg/core/diagnostics"
	"github.com/adedayo/checkmate/pkg/core/projects"
	secrets "github.com/adedayo/checkmate/pkg/plugin/secrets-finder/pkg"
	"github.com/adedayo/checkmate/pkg/store"
	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
)

const workspaceExclusionFilename = ".checkmate.yaml"

// compositeExclusions merges:
//  1. Built-in common exclusions (secrets.MakeCommonExclusions)
//  2. Optional explicit --exclusion YAML file
//  3. Workspace .checkmate.yaml files (with mtime tracking)
//  4. Active SQLite exceptions for matching workspace projects + global scope
type compositeExclusions struct {
	mu             sync.RWMutex
	exclusionFile  string
	extraProvider  diagnostics.ExclusionProvider
	store          store.PlatformStore
	workspacePaths []string
	provider       diagnostics.ExclusionProvider
	mtimes         map[string]time.Time
}

func newCompositeExclusions(exclusionFile string, extraProvider diagnostics.ExclusionProvider, s store.PlatformStore) *compositeExclusions {
	ce := &compositeExclusions{
		exclusionFile: exclusionFile,
		extraProvider: extraProvider,
		store:         s,
		mtimes:        make(map[string]time.Time),
	}
	ce.Reload()
	return ce
}

func (ce *compositeExclusions) SetWorkspaces(paths []string) {
	ce.mu.Lock()
	cleaned := make([]string, 0, len(paths))
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if abs, err := filepath.Abs(p); err == nil {
			p = abs
		}
		cleaned = append(cleaned, p)
	}
	ce.workspacePaths = cleaned
	ce.mu.Unlock()
	ce.Reload()
}

// Provider returns the active ExclusionProvider, automatically reloading if a
// workspace .checkmate.yaml file changed on disk.
func (ce *compositeExclusions) Provider() diagnostics.ExclusionProvider {
	if ce.yamlMtimesChanged() {
		ce.Reload()
	}
	ce.mu.RLock()
	p := ce.provider
	extra := ce.extraProvider
	ce.mu.RUnlock()
	if p == nil {
		p = diagnostics.MakeEmptyExcludes()
	}
	if extra == nil {
		return p
	}
	return mergedProvider{primary: p, secondary: extra}
}

func (ce *compositeExclusions) yamlMtimesChanged() bool {
	ce.mu.RLock()
	paths := append([]string(nil), ce.workspacePaths...)
	exclFile := ce.exclusionFile
	prev := ce.mtimes
	ce.mu.RUnlock()

	candidates := make([]string, 0, len(paths)+1)
	if exclFile != "" {
		candidates = append(candidates, exclFile)
	}
	for _, wp := range paths {
		candidates = append(candidates, filepath.Join(wp, workspaceExclusionFilename))
	}

	for _, f := range candidates {
		info, err := os.Stat(f)
		prevT, hadPrev := prev[f]
		if err != nil {
			if hadPrev {
				return true
			}
			continue
		}
		if !hadPrev || !info.ModTime().Equal(prevT) {
			return true
		}
	}
	return false
}

// Reload rebuilds the compiled ExclusionProvider from common exclusions,
// YAML files, and active SQLite exceptions.
func (ce *compositeExclusions) Reload() {
	ce.mu.RLock()
	wsPaths := append([]string(nil), ce.workspacePaths...)
	exclFile := ce.exclusionFile
	s := ce.store
	ce.mu.RUnlock()

	def := secrets.MakeCommonExclusions()
	if def.PerFileExcludedStrings == nil {
		def.PerFileExcludedStrings = make(map[string][]string)
	}
	if def.PerFileExcludedHashes == nil {
		def.PerFileExcludedHashes = make(map[string][]string)
	}
	if def.PathRegexExcludedRegExs == nil {
		def.PathRegexExcludedRegExs = make(map[string][]string)
	}

	newMtimes := make(map[string]time.Time)

	loadYAML := func(path string) {
		info, err := os.Stat(path)
		if err != nil {
			return
		}
		newMtimes[path] = info.ModTime()
		data, err := os.ReadFile(path)
		if err != nil {
			log.Printf("lsp: warning reading exclusion file %s: %v", path, err)
			return
		}
		var parsed diagnostics.ExcludeDefinition
		if err := yaml.Unmarshal(data, &parsed); err != nil {
			log.Printf("lsp: warning parsing exclusion file %s: %v", path, err)
			return
		}
		def = secrets.MergeExclusions(parsed, def)
	}

	if exclFile != "" {
		loadYAML(exclFile)
	}
	for _, wp := range wsPaths {
		loadYAML(filepath.Join(wp, workspaceExclusionFilename))
	}

	if s != nil {
		ce.mergeStoreExceptions(s, wsPaths, &def)
	}

	compiled, err := diagnostics.CompileExcludes(diagnostics.ExcludeContainer{
		ExcludeDef:   &def,
		Repositories: wsPaths,
	})
	if err != nil {
		log.Printf("lsp: warning compiling exclusions: %v", err)
		compiled = diagnostics.MakeEmptyExcludes()
	}

	ce.mu.Lock()
	ce.provider = compiled
	ce.mtimes = newMtimes
	ce.mu.Unlock()
}

func (ce *compositeExclusions) mergeStoreExceptions(s store.PlatformStore, wsPaths []string, def *diagnostics.ExcludeDefinition) {
	projectIDs := matchingProjectIDs(s, wsPaths)
	// Always include global exceptions (project_id == "").
	projectIDs = append(projectIDs, "")

	seen := make(map[string]struct{})
	for _, pid := range projectIDs {
		exceptions, err := s.ListExceptions(pid)
		if err != nil {
			continue
		}
		for _, exc := range exceptions {
			if exc == nil || exc.Status != "active" || exc.Scope == nil {
				continue
			}
			if _, dup := seen[exc.ID]; dup {
				continue
			}
			seen[exc.ID] = struct{}{}
			applyExceptionToDef(exc, wsPaths, def)
		}
	}
}

func matchingProjectIDs(s store.PlatformStore, wsPaths []string) []string {
	if s == nil || len(wsPaths) == 0 {
		return nil
	}
	var ids []string
	for _, ps := range s.ListProjectSummaries() {
		proj, err := s.GetProject(ps.ID)
		if err != nil {
			continue
		}
		if projectMatchesAnyWorkspace(proj, wsPaths) {
			ids = append(ids, proj.ID)
		}
	}
	return ids
}

func projectMatchesAnyWorkspace(proj projects.Project, wsPaths []string) bool {
	for _, repo := range proj.Repositories {
		loc := strings.TrimSpace(repo.Location)
		if loc == "" {
			continue
		}
		if abs, err := filepath.Abs(loc); err == nil {
			loc = abs
		}
		for _, wp := range wsPaths {
			if sameOrNestedPath(loc, wp) || sameOrNestedPath(wp, loc) {
				return true
			}
		}
	}
	return false
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

func applyExceptionToDef(exc *store.Exception, wsPaths []string, def *diagnostics.ExcludeDefinition) {
	sc := exc.Scope
	pathVariants := func(p string) []string {
		variants := []string{p}
		for _, wp := range wsPaths {
			if trimmed := strings.TrimPrefix(p, wp); trimmed != p {
				variants = appendUnique(variants, trimmed)
				variants = appendUnique(variants, strings.TrimPrefix(trimmed, string(os.PathSeparator)))
			}
		}
		return variants
	}
	switch sc.Type {
	case "globalHash", "value":
		if sc.SecretChecksum != "" {
			def.GloballyExcludedHashes = append(def.GloballyExcludedHashes, sc.SecretChecksum)
		}
	case "globalString":
		if sc.StringMatch != "" {
			def.GloballyExcludedStrings = append(def.GloballyExcludedStrings, sc.StringMatch)
		}
	case "globalRegex":
		if sc.RegexMatch != "" {
			def.GloballyExcludedRegExs = append(def.GloballyExcludedRegExs, sc.RegexMatch)
		}
	case "pathRegex":
		if sc.RegexMatch != "" {
			def.PathExclusionRegExs = append(def.PathExclusionRegExs, sc.RegexMatch)
		}
	case "pathString":
		if sc.Path != "" && sc.StringMatch != "" {
			for _, pv := range pathVariants(sc.Path) {
				def.PerFileExcludedStrings[pv] = append(def.PerFileExcludedStrings[pv], sc.StringMatch)
			}
		}
	case "pathHash":
		if sc.Path != "" && sc.SecretChecksum != "" {
			for _, pv := range pathVariants(sc.Path) {
				def.PerFileExcludedHashes[pv] = append(def.PerFileExcludedHashes[pv], sc.SecretChecksum)
			}
		}
	case "pathRegexRegex":
		if sc.Path != "" && sc.RegexMatch != "" {
			def.PathRegexExcludedRegExs[sc.Path] = append(def.PathRegexExcludedRegExs[sc.Path], sc.RegexMatch)
		}
	}
}

// PersistSuppression writes a Quick Fix suppression to SQLite (with audit_log)
// when a store is attached, or to <workspaceRoot>/.checkmate.yaml when --no-db
// is set. Plaintext secret values are never persisted.
func (ce *compositeExclusions) PersistSuppression(cmdName, filePath, secretChecksum, ruleID string) error {
	ce.mu.RLock()
	s := ce.store
	wsPaths := append([]string(nil), ce.workspacePaths...)
	ce.mu.RUnlock()

	wsRoot := ce.workspaceRootForFile(filePath, wsPaths)

	if s != nil {
		if err := ce.persistToStore(s, wsRoot, cmdName, filePath, secretChecksum, ruleID); err != nil {
			return err
		}
		ce.Reload()
		return nil
	}

	if err := ce.persistToYAML(wsRoot, cmdName, filePath, secretChecksum); err != nil {
		return err
	}
	ce.Reload()
	return nil
}

func (ce *compositeExclusions) workspaceRootForFile(filePath string, wsPaths []string) string {
	for _, wp := range wsPaths {
		if sameOrNestedPath(filePath, wp) {
			return wp
		}
	}
	if len(wsPaths) > 0 {
		return wsPaths[0]
	}
	if filePath != "" {
		return filepath.Dir(filePath)
	}
	return "."
}

func (ce *compositeExclusions) persistToStore(s store.PlatformStore, wsRoot, cmdName, filePath, secretChecksum, ruleID string) error {
	projectID := ""
	ids := matchingProjectIDs(s, []string{wsRoot})
	if len(ids) > 0 {
		projectID = ids[0]
	} else if wsRoot != "" {
		name := filepath.Base(wsRoot)
		if name == "" || name == "." || name == "/" {
			name = "lsp-workspace"
		}
		proj, err := s.CreateProject(projects.ProjectDescription{
			Name:      name,
			Workspace: "default",
			Repositories: []projects.Repository{
				{Location: wsRoot, LocationType: "filesystem"},
			},
		})
		if err != nil {
			return fmt.Errorf("create workspace project: %w", err)
		}
		projectID = proj.ID
	}

	if ruleID == "" {
		ruleID = "*"
	}

	var scope *store.ExceptionScopeDetail
	var details string
	switch cmdName {
	case CmdSuppressPathHash:
		if secretChecksum == "" || filePath == "" {
			return fmt.Errorf("file path and secret checksum are required for %s", cmdName)
		}
		scope = &store.ExceptionScopeDetail{
			Type:           "pathHash",
			Path:           filePath,
			SecretChecksum: secretChecksum,
		}
		details = fmt.Sprintf("LSP Quick Fix suppressed hash %s in %s", secretChecksum, filePath)
	case CmdSuppressGlobalHash:
		if secretChecksum == "" {
			return fmt.Errorf("secret checksum is required for %s", cmdName)
		}
		scope = &store.ExceptionScopeDetail{
			Type:           "globalHash",
			SecretChecksum: secretChecksum,
		}
		details = fmt.Sprintf("LSP Quick Fix suppressed hash %s across project", secretChecksum)
	case CmdExcludeFile:
		if filePath == "" {
			return fmt.Errorf("file path is required for %s", cmdName)
		}
		scope = &store.ExceptionScopeDetail{
			Type:       "pathRegex",
			RegexMatch: "^" + regexp.QuoteMeta(filePath) + "$",
		}
		details = fmt.Sprintf("LSP Quick Fix excluded file %s", filePath)
	default:
		return fmt.Errorf("unsupported command %q", cmdName)
	}

	now := time.Now().UTC()
	exc := &store.Exception{
		ID:            "exc_" + uuid.New().String()[:12],
		ProjectID:     projectID,
		RuleID:        ruleID,
		Scope:         scope,
		Reason:        "false_positive_pattern",
		Justification: details,
		CreatedBy:     "lsp:editor",
		CreatedAt:     now,
		Status:        "active",
		Tags:          []string{"lsp-quickfix"},
		AuditTrail: []*store.AuditEvent{
			{
				Action:    "exception.created",
				Timestamp: now,
				User:      "lsp:editor",
				Details:   details,
			},
		},
	}
	if err := s.CreateException(exc); err != nil {
		return fmt.Errorf("persist exception: %w", err)
	}
	_ = s.RecordAuditEvent(&store.AuditEvent{
		Action:    "exception.created",
		Timestamp: now,
		User:      "lsp:editor",
		Details:   details,
	}, "exception", exc.ID)
	return nil
}

func (ce *compositeExclusions) persistToYAML(wsRoot, cmdName, filePath, secretChecksum string) error {
	yamlPath := filepath.Join(wsRoot, workspaceExclusionFilename)
	var def diagnostics.ExcludeDefinition
	if data, err := os.ReadFile(yamlPath); err == nil {
		_ = yaml.Unmarshal(data, &def)
	}
	if def.PerFileExcludedHashes == nil {
		def.PerFileExcludedHashes = make(map[string][]string)
	}

	switch cmdName {
	case CmdSuppressPathHash:
		if secretChecksum == "" || filePath == "" {
			return fmt.Errorf("file path and secret checksum are required for %s", cmdName)
		}
		key := filePath
		if wsRoot != "" && sameOrNestedPath(filePath, wsRoot) {
			if trimmed := strings.TrimPrefix(filePath, wsRoot); trimmed != "" {
				key = trimmed
			}
		}
		def.PerFileExcludedHashes[key] = appendUnique(def.PerFileExcludedHashes[key], secretChecksum)
	case CmdSuppressGlobalHash:
		if secretChecksum == "" {
			return fmt.Errorf("secret checksum is required for %s", cmdName)
		}
		def.GloballyExcludedHashes = appendUnique(def.GloballyExcludedHashes, secretChecksum)
	case CmdExcludeFile:
		if filePath == "" {
			return fmt.Errorf("file path is required for %s", cmdName)
		}
		pattern := "^" + regexp.QuoteMeta(filePath) + "$"
		def.PathExclusionRegExs = appendUnique(def.PathExclusionRegExs, pattern)
	default:
		return fmt.Errorf("unsupported command %q", cmdName)
	}

	encoded, err := yaml.Marshal(&def)
	if err != nil {
		return fmt.Errorf("marshal %s: %w", yamlPath, err)
	}
	return os.WriteFile(yamlPath, encoded, 0600)
}

func appendUnique(slice []string, val string) []string {
	for _, s := range slice {
		if s == val {
			return slice
		}
	}
	return append(slice, val)
}

// mergedProvider combines two ExclusionProviders via logical OR.
type mergedProvider struct {
	primary   diagnostics.ExclusionProvider
	secondary diagnostics.ExclusionProvider
}

func (m mergedProvider) ShouldExclude(path, value string) bool {
	return m.primary.ShouldExclude(path, value) || m.secondary.ShouldExclude(path, value)
}

func (m mergedProvider) ShouldExcludePath(path string) bool {
	return m.primary.ShouldExcludePath(path) || m.secondary.ShouldExcludePath(path)
}

func (m mergedProvider) ShouldExcludeValue(value string) bool {
	return m.primary.ShouldExcludeValue(value) || m.secondary.ShouldExcludeValue(value)
}

func (m mergedProvider) ShouldExcludeHash(hash string) bool {
	return m.primary.ShouldExcludeHash(hash) || m.secondary.ShouldExcludeHash(hash)
}

func (m mergedProvider) ShouldExcludeHashOnPath(path, hash string) bool {
	return m.primary.ShouldExcludeHashOnPath(path, hash) || m.secondary.ShouldExcludeHashOnPath(path, hash)
}
