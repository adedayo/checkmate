package lsp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/adedayo/checkmate/pkg/core/diagnostics"
	"github.com/adedayo/checkmate/pkg/core/util"
	secrets "github.com/adedayo/checkmate/pkg/plugin/secrets-finder/pkg"
	"github.com/adedayo/checkmate/pkg/store"
)

const defaultDebounceDuration = 150 * time.Millisecond

// ServerOptions configures the CheckMate LSP 3.17 server.
type ServerOptions struct {
	ExclusionFile        string
	ExclusionProvider    diagnostics.ExclusionProvider
	Store                store.PlatformStore
	DisableWorkspaceScan bool
	Debounce             time.Duration
	Version              string
}

type openDocument struct {
	uri     string
	path    string
	version int
	text    string
	timer   *time.Timer
	cancel  context.CancelFunc
}

// Server implements CheckMate's LSP 3.17 Language Server over stdio.
type Server struct {
	opts       ServerOptions
	exclusions *compositeExclusions
	debounce   time.Duration

	writeMu sync.Mutex
	writer  io.Writer

	mu               sync.Mutex
	workCtx          context.Context
	workCancel       context.CancelFunc
	workspacePaths   []string
	openDocs         map[string]*openDocument
	publishedURIs    map[string]struct{}
	workspaceURIs    map[string]struct{}
	shutdownReceived bool
	exitRequested    bool
	wg               sync.WaitGroup
}

// NewServer constructs a configured CheckMate LSP 3.17 server.
func NewServer(opts ServerOptions) *Server {
	if opts.Version == "" {
		opts.Version = "dev"
	}
	return &Server{
		opts:          opts,
		exclusions:    newCompositeExclusions(opts.ExclusionFile, opts.ExclusionProvider, opts.Store),
		debounce:      resolveDebounce(opts.Debounce),
		openDocs:      make(map[string]*openDocument),
		publishedURIs: make(map[string]struct{}),
		workspaceURIs: make(map[string]struct{}),
	}
}

// NewSecurityServer is a backward-compatible constructor returning *Server.
func NewSecurityServer(exclusionProvider diagnostics.ExclusionProvider) *Server {
	return NewServer(ServerOptions{
		ExclusionProvider: exclusionProvider,
	})
}

func resolveDebounce(explicit time.Duration) time.Duration {
	if explicit > 0 {
		return explicit
	}
	if v := strings.TrimSpace(os.Getenv("CHECKMATE_LSP_DEBOUNCE_MS")); v != "" {
		if ms, err := strconv.Atoi(v); err == nil && ms >= 0 {
			return time.Duration(ms) * time.Millisecond
		}
	}
	return defaultDebounceDuration
}

// Start runs the LSP server until EOF or exit, discarding the exit code.
func (s *Server) Start(r io.Reader, w io.Writer) {
	_, _ = s.Serve(context.Background(), r, w)
}

// Serve processes Content-Length framed LSP 3.17 JSON-RPC 2.0 traffic on r and w.
// It returns exit code 0 when shutdown preceded exit (or clean EOF), or 1 if
// exit was received without a prior shutdown request.
func (s *Server) Serve(ctx context.Context, r io.Reader, w io.Writer) (int, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	workCtx, workCancel := context.WithCancel(ctx)
	s.mu.Lock()
	s.writer = w
	s.workCtx = workCtx
	s.workCancel = workCancel
	s.mu.Unlock()

	defer func() {
		workCancel()
		s.stopAllTimers()
		s.wg.Wait()
	}()

	reader := bufio.NewReader(r)
	for {
		if ctx.Err() != nil {
			return s.exitCode(), ctx.Err()
		}

		raw, err := readMessage(reader)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return s.exitCode(), nil
			}
			return 1, err
		}

		var req RPCRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			_ = s.sendError(json.RawMessage("null"), ErrCodeParseError, "parse error: "+err.Error())
			continue
		}

		if shouldExit := s.handleMessage(&req); shouldExit {
			return s.exitCode(), nil
		}
	}
}

func (s *Server) exitCode() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.exitRequested && !s.shutdownReceived {
		return 1
	}
	return 0
}

func (s *Server) stopAllTimers() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, doc := range s.openDocs {
		if doc.timer != nil {
			doc.timer.Stop()
		}
		if doc.cancel != nil {
			doc.cancel()
		}
	}
}

func (s *Server) handleMessage(req *RPCRequest) (shouldExit bool) {
	switch req.Method {
	case "exit":
		s.mu.Lock()
		s.exitRequested = true
		if s.workCancel != nil {
			s.workCancel()
		}
		s.mu.Unlock()
		return true

	case "shutdown":
		s.mu.Lock()
		s.shutdownReceived = true
		if s.workCancel != nil {
			s.workCancel()
		}
		s.mu.Unlock()
		s.stopAllTimers()
		_ = s.sendResult(req.ID, nil)
		return false
	}

	s.mu.Lock()
	isShutdown := s.shutdownReceived
	s.mu.Unlock()
	if isShutdown {
		if !req.IsNotification() {
			_ = s.sendError(req.ID, ErrCodeInvalidRequest, "server is shutting down")
		}
		return false
	}

	switch req.Method {
	case "initialize":
		s.handleInitialize(req)
	case "initialized":
		s.handleInitialized()
	case "textDocument/didOpen":
		s.handleDidOpen(req)
	case "textDocument/didChange":
		s.handleDidChange(req)
	case "textDocument/didSave":
		s.handleDidSave(req)
	case "textDocument/didClose":
		s.handleDidClose(req)
	case "workspace/didChangeWatchedFiles":
		s.handleDidChangeWatchedFiles(req)
	case "workspace/didChangeWorkspaceFolders":
		s.handleDidChangeWorkspaceFolders(req)
	case "textDocument/codeAction":
		s.handleCodeAction(req)
	case "workspace/executeCommand":
		s.handleExecuteCommand(req)
	case "$/cancelRequest", "$/setTrace":
		// Accepted notifications; no response required.
	default:
		if !req.IsNotification() {
			_ = s.sendError(req.ID, ErrCodeMethodNotFound, fmt.Sprintf("method not found: %s", req.Method))
		}
	}
	return false
}

func (s *Server) handleInitialize(req *RPCRequest) {
	var params InitializeParams
	if len(req.Params) > 0 {
		_ = json.Unmarshal(req.Params, &params)
	}

	var paths []string
	for _, folder := range params.WorkspaceFolders {
		if p, err := FileURIToPath(folder.URI); err == nil && p != "" {
			paths = append(paths, p)
		}
	}
	if len(paths) == 0 && params.RootURI != "" {
		if p, err := FileURIToPath(params.RootURI); err == nil && p != "" {
			paths = append(paths, p)
		}
	}
	if len(paths) == 0 && params.RootPath != "" {
		paths = append(paths, params.RootPath)
	}

	s.mu.Lock()
	s.workspacePaths = paths
	s.mu.Unlock()
	s.exclusions.SetWorkspaces(paths)

	result := InitializeResult{
		Capabilities: ServerCapabilities{
			TextDocumentSync: &TextDocumentSyncOptions{
				OpenClose: true,
				Change:    TextDocumentSyncKindFull,
				Save:      &SaveOptions{IncludeText: true},
			},
			CodeActionProvider: &CodeActionOptions{
				CodeActionKinds: []string{"quickfix"},
			},
			ExecuteCommandProvider: &ExecuteCommandOptions{
				Commands: []string{
					CmdSuppressPathHash,
					CmdSuppressGlobalHash,
					CmdExcludeFile,
				},
			},
			Workspace: &WorkspaceServerCapabilities{
				WorkspaceFolders: &WorkspaceFoldersServerCapabilities{
					Supported:           true,
					ChangeNotifications: true,
				},
			},
		},
		ServerInfo: &ServerInfo{
			Name:    "checkmate",
			Version: s.opts.Version,
		},
	}
	_ = s.sendResult(req.ID, result)
}

func (s *Server) handleInitialized() {
	if s.opts.DisableWorkspaceScan {
		return
	}
	s.triggerWorkspaceScan()
}

func (s *Server) triggerWorkspaceScan() {
	s.mu.Lock()
	paths := append([]string(nil), s.workspacePaths...)
	ctx := s.workCtx
	if ctx == nil || ctx.Err() != nil || len(paths) == 0 {
		s.mu.Unlock()
		return
	}
	s.wg.Add(1)
	s.mu.Unlock()

	go func() {
		defer s.wg.Done()
		s.scanWorkspace(ctx, paths)
	}()
}

func (s *Server) scanWorkspace(ctx context.Context, paths []string) {
	if ctx.Err() != nil || len(paths) == 0 {
		return
	}

	excl := s.exclusions.Provider()
	secOpts := secrets.SecretSearchOptions{
		ShowSource:        false,
		CalculateChecksum: true,
		Exclusions:        excl,
	}

	diagCh, pathsCh, _ := secrets.SearchSecretsOnPathsWithReport(ctx, paths, secOpts, "", "", nil)

	byFile := make(map[string][]*diagnostics.SecurityDiagnostic)
	for d := range diagCh {
		if ctx.Err() != nil {
			continue
		}
		if d == nil || d.Location == nil || *d.Location == "" {
			continue
		}
		loc := *d.Location
		byFile[loc] = append(byFile[loc], d)
	}
	<-pathsCh

	if ctx.Err() != nil {
		return
	}

	newWorkspaceURIs := make(map[string]struct{}, len(byFile))

	for filePath, list := range byFile {
		uri := PathToFileURI(filePath)
		newWorkspaceURIs[uri] = struct{}{}

		// Never overwrite newer in-memory diagnostics for currently open documents.
		s.mu.Lock()
		_, isOpen := s.openDocs[uri]
		s.mu.Unlock()
		if isOpen {
			continue
		}

		diagnostics.SortDiagnosticsCanonically(list)
		converted := make([]Diagnostic, 0, len(list))
		for _, d := range list {
			converted = append(converted, convertDiagnostic(d, filePath))
		}
		s.publishDiagnostics(uri, nil, converted)
	}

	// Clear any previously workspace-flagged URIs that are now clean.
	s.mu.Lock()
	prevWS := s.workspaceURIs
	s.workspaceURIs = newWorkspaceURIs
	var toClear []string
	for oldURI := range prevWS {
		if _, stillFlagged := newWorkspaceURIs[oldURI]; !stillFlagged {
			if _, isOpen := s.openDocs[oldURI]; !isOpen {
				toClear = append(toClear, oldURI)
			}
		}
	}
	s.mu.Unlock()

	for _, uri := range toClear {
		s.publishDiagnostics(uri, nil, []Diagnostic{})
	}
}

func (s *Server) handleDidOpen(req *RPCRequest) {
	var params DidOpenTextDocumentParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return
	}
	uri := params.TextDocument.URI
	filePath, err := FileURIToPath(uri)
	if err != nil {
		log.Printf("lsp: didOpen invalid URI %q: %v", uri, err)
		return
	}

	s.mu.Lock()
	if existing, ok := s.openDocs[uri]; ok {
		if existing.timer != nil {
			existing.timer.Stop()
		}
		if existing.cancel != nil {
			existing.cancel()
		}
	}
	doc := &openDocument{
		uri:     uri,
		path:    filePath,
		version: params.TextDocument.Version,
		text:    params.TextDocument.Text,
	}
	s.openDocs[uri] = doc
	s.mu.Unlock()

	s.scheduleDocumentScan(uri, doc.version, doc.path, doc.text, 0)
}

func (s *Server) handleDidChange(req *RPCRequest) {
	var params DidChangeTextDocumentParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return
	}
	if len(params.ContentChanges) == 0 {
		return
	}
	uri := params.TextDocument.URI
	latestText := params.ContentChanges[len(params.ContentChanges)-1].Text

	s.mu.Lock()
	doc, ok := s.openDocs[uri]
	if !ok {
		filePath, err := FileURIToPath(uri)
		if err != nil {
			s.mu.Unlock()
			return
		}
		doc = &openDocument{uri: uri, path: filePath}
		s.openDocs[uri] = doc
	}
	if doc.timer != nil {
		doc.timer.Stop()
		doc.timer = nil
	}
	if doc.cancel != nil {
		doc.cancel()
		doc.cancel = nil
	}
	doc.version = params.TextDocument.Version
	doc.text = latestText
	path := doc.path
	version := doc.version
	s.mu.Unlock()

	s.scheduleDocumentScan(uri, version, path, latestText, s.debounce)
}

func (s *Server) handleDidSave(req *RPCRequest) {
	var params DidSaveTextDocumentParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return
	}
	uri := params.TextDocument.URI

	s.mu.Lock()
	doc, ok := s.openDocs[uri]
	if ok {
		if doc.timer != nil {
			doc.timer.Stop()
			doc.timer = nil
		}
		if doc.cancel != nil {
			doc.cancel()
			doc.cancel = nil
		}
		if params.Text != nil {
			doc.text = *params.Text
		}
		path := doc.path
		version := doc.version
		text := doc.text
		s.mu.Unlock()
		s.scheduleDocumentScan(uri, version, path, text, 0)
		return
	}
	s.mu.Unlock()

	filePath, err := FileURIToPath(uri)
	if err != nil {
		return
	}
	var text string
	if params.Text != nil {
		text = *params.Text
	} else if data, err := os.ReadFile(filePath); err == nil {
		text = string(data)
	}
	s.scheduleDocumentScan(uri, 0, filePath, text, 0)
}

func (s *Server) handleDidClose(req *RPCRequest) {
	var params DidCloseTextDocumentParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return
	}
	uri := params.TextDocument.URI

	s.mu.Lock()
	if doc, ok := s.openDocs[uri]; ok {
		if doc.timer != nil {
			doc.timer.Stop()
		}
		if doc.cancel != nil {
			doc.cancel()
		}
		delete(s.openDocs, uri)
	}
	_, ownedByWorkspace := s.workspaceURIs[uri]
	s.mu.Unlock()

	if !ownedByWorkspace {
		s.publishDiagnostics(uri, nil, []Diagnostic{})
	}
}

func (s *Server) handleDidChangeWatchedFiles(req *RPCRequest) {
	var params DidChangeWatchedFilesParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return
	}
	reload := false
	for _, ch := range params.Changes {
		if strings.HasSuffix(ch.URI, workspaceExclusionFilename) {
			reload = true
			break
		}
	}
	if reload {
		s.exclusions.Reload()
		s.rescanAllOpenDocuments()
		if !s.opts.DisableWorkspaceScan {
			s.triggerWorkspaceScan()
		}
	}
}

func (s *Server) handleDidChangeWorkspaceFolders(req *RPCRequest) {
	var params DidChangeWorkspaceFoldersParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return
	}
	s.mu.Lock()
	current := make(map[string]struct{}, len(s.workspacePaths))
	for _, p := range s.workspacePaths {
		current[p] = struct{}{}
	}
	for _, rem := range params.Event.Removed {
		if p, err := FileURIToPath(rem.URI); err == nil {
			delete(current, p)
		}
	}
	for _, add := range params.Event.Added {
		if p, err := FileURIToPath(add.URI); err == nil && p != "" {
			current[p] = struct{}{}
		}
	}
	updated := make([]string, 0, len(current))
	for p := range current {
		updated = append(updated, p)
	}
	s.workspacePaths = updated
	s.mu.Unlock()

	s.exclusions.SetWorkspaces(updated)
	if !s.opts.DisableWorkspaceScan {
		s.triggerWorkspaceScan()
	}
}

func (s *Server) scheduleDocumentScan(uri string, version int, filePath, content string, delay time.Duration) {
	s.mu.Lock()
	baseCtx := s.workCtx
	if baseCtx == nil || baseCtx.Err() != nil {
		s.mu.Unlock()
		return
	}
	scanCtx, cancel := context.WithCancel(baseCtx)
	if doc, ok := s.openDocs[uri]; ok {
		if doc.cancel != nil {
			doc.cancel()
		}
		doc.cancel = cancel
	}

	run := func() {
		defer s.wg.Done()
		defer cancel()
		if scanCtx.Err() != nil {
			return
		}
		diags := s.scanDocument(scanCtx, filePath, content)
		if scanCtx.Err() != nil {
			return
		}
		// Verify document version has not moved on since scan started.
		s.mu.Lock()
		if doc, ok := s.openDocs[uri]; ok && doc.version != version {
			s.mu.Unlock()
			return
		}
		s.mu.Unlock()

		var verPtr *int
		if version > 0 {
			v := version
			verPtr = &v
		}
		s.publishDiagnostics(uri, verPtr, diags)
	}

	if delay <= 0 {
		s.wg.Add(1)
		s.mu.Unlock()
		go run()
		return
	}

	var timer *time.Timer
	timer = time.AfterFunc(delay, func() {
		s.mu.Lock()
		doc, ok := s.openDocs[uri]
		if !ok || doc.timer != timer || doc.version != version || s.workCtx == nil || s.workCtx.Err() != nil {
			s.mu.Unlock()
			cancel()
			return
		}
		doc.timer = nil
		s.wg.Add(1)
		s.mu.Unlock()
		run()
	})
	if doc, ok := s.openDocs[uri]; ok {
		doc.timer = timer
	}
	s.mu.Unlock()
}

func (s *Server) scanDocument(ctx context.Context, filePath, content string) []Diagnostic {
	if ctx.Err() != nil {
		return []Diagnostic{}
	}

	excl := s.exclusions.Provider()
	if excl.ShouldExcludePath(filePath) {
		return []Diagnostic{}
	}

	secOpts := secrets.SecretSearchOptions{
		ShowSource:        false,
		CalculateChecksum: true,
		Exclusions:        excl,
	}

	ext := filepath.Ext(filePath)
	finder := secrets.GetFinderForFileType(ext, secOpts)
	rif := util.RepositoryIndexedFile{
		File:            filePath,
		RepositoryIndex: 0,
	}

	var raw []*diagnostics.SecurityDiagnostic
	for d := range secrets.FindSecret(rif, strings.NewReader(content), finder, false) {
		if ctx.Err() != nil {
			return []Diagnostic{}
		}
		if d == nil {
			continue
		}
		loc := filePath
		d.Location = &loc
		val := d.GetValue()
		if excl.ShouldExclude(filePath, val) {
			continue
		}
		if d.SHA256 != nil && excl.ShouldExcludeHashOnPath(filePath, *d.SHA256) {
			continue
		}
		raw = append(raw, d)
	}

	if len(raw) == 0 {
		return []Diagnostic{}
	}

	raw = diagnostics.SubsumeOverlapping(raw)
	diagnostics.SortDiagnosticsCanonically(raw)

	out := make([]Diagnostic, 0, len(raw))
	for _, d := range raw {
		out = append(out, convertDiagnostic(d, filePath))
	}
	return out
}

func (s *Server) rescanAllOpenDocuments() {
	s.mu.Lock()
	type snap struct {
		uri     string
		path    string
		version int
		text    string
	}
	snaps := make([]snap, 0, len(s.openDocs))
	for _, doc := range s.openDocs {
		snaps = append(snaps, snap{
			uri:     doc.uri,
			path:    doc.path,
			version: doc.version,
			text:    doc.text,
		})
	}
	s.mu.Unlock()

	for _, sn := range snaps {
		s.scheduleDocumentScan(sn.uri, sn.version, sn.path, sn.text, 0)
	}
}

type quickFixCommandArg struct {
	URI            string `json:"uri"`
	FilePath       string `json:"filePath"`
	FindingID      string `json:"findingId,omitempty"`
	SecretChecksum string `json:"secretChecksum,omitempty"`
	RuleID         string `json:"ruleId,omitempty"`
}

func (s *Server) handleCodeAction(req *RPCRequest) {
	var params CodeActionParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		_ = s.sendError(req.ID, ErrCodeInvalidParams, "invalid codeAction params: "+err.Error())
		return
	}

	filePath, err := FileURIToPath(params.TextDocument.URI)
	if err != nil {
		_ = s.sendResult(req.ID, []CodeAction{})
		return
	}

	actions := []CodeAction{}
	seenFileAction := false
	seenChecksum := make(map[string]struct{})

	for _, diag := range params.Context.Diagnostics {
		if diag.Source != diagnosticSource || diag.Data == nil {
			continue
		}
		arg := quickFixCommandArg{
			URI:            params.TextDocument.URI,
			FilePath:       filePath,
			FindingID:      diag.Data.FindingID,
			SecretChecksum: diag.Data.SecretChecksum,
			RuleID:         diag.Data.RuleID,
		}

		if diag.Data.SecretChecksum != "" {
			if _, dup := seenChecksum[diag.Data.SecretChecksum]; !dup {
				seenChecksum[diag.Data.SecretChecksum] = struct{}{}
				actions = append(actions,
					CodeAction{
						Title:       "CheckMate: Suppress this value in this file",
						Kind:        "quickfix",
						Diagnostics: []Diagnostic{diag},
						Command: &Command{
							Title:     "CheckMate: Suppress this value in this file",
							Command:   CmdSuppressPathHash,
							Arguments: []interface{}{arg},
						},
					},
					CodeAction{
						Title:       "CheckMate: Suppress this value across project",
						Kind:        "quickfix",
						Diagnostics: []Diagnostic{diag},
						Command: &Command{
							Title:     "CheckMate: Suppress this value across project",
							Command:   CmdSuppressGlobalHash,
							Arguments: []interface{}{arg},
						},
					},
				)
			}
		}

		if !seenFileAction {
			seenFileAction = true
			actions = append(actions, CodeAction{
				Title:       "CheckMate: Exclude this file from secret scanning",
				Kind:        "quickfix",
				Diagnostics: []Diagnostic{diag},
				Command: &Command{
					Title:     "CheckMate: Exclude this file from secret scanning",
					Command:   CmdExcludeFile,
					Arguments: []interface{}{arg},
				},
			})
		}
	}

	_ = s.sendResult(req.ID, actions)
}

func (s *Server) handleExecuteCommand(req *RPCRequest) {
	var params ExecuteCommandParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		_ = s.sendError(req.ID, ErrCodeInvalidParams, "invalid executeCommand params: "+err.Error())
		return
	}

	switch params.Command {
	case CmdSuppressPathHash, CmdSuppressGlobalHash, CmdExcludeFile:
		if len(params.Arguments) == 0 {
			_ = s.sendError(req.ID, ErrCodeInvalidParams, "missing command arguments")
			return
		}
		var arg quickFixCommandArg
		if err := json.Unmarshal(params.Arguments[0], &arg); err != nil {
			_ = s.sendError(req.ID, ErrCodeInvalidParams, "invalid command argument: "+err.Error())
			return
		}
		if arg.FilePath == "" && arg.URI != "" {
			if p, err := FileURIToPath(arg.URI); err == nil {
				arg.FilePath = p
			}
		}

		if err := s.exclusions.PersistSuppression(params.Command, arg.FilePath, arg.SecretChecksum, arg.RuleID); err != nil {
			_ = s.sendError(req.ID, ErrCodeInternalError, err.Error())
			return
		}

		s.rescanAllOpenDocuments()
		if !s.opts.DisableWorkspaceScan {
			s.triggerWorkspaceScan()
		}
		_ = s.sendResult(req.ID, map[string]interface{}{"status": "ok"})

	default:
		_ = s.sendError(req.ID, ErrCodeInvalidParams, fmt.Sprintf("unknown command: %s", params.Command))
	}
}

func (s *Server) publishDiagnostics(uri string, version *int, diags []Diagnostic) {
	if diags == nil {
		diags = []Diagnostic{}
	}
	s.mu.Lock()
	if len(diags) > 0 {
		s.publishedURIs[uri] = struct{}{}
	} else {
		delete(s.publishedURIs, uri)
	}
	s.mu.Unlock()

	_ = s.sendNotification("textDocument/publishDiagnostics", PublishDiagnosticsParams{
		URI:         uri,
		Version:     version,
		Diagnostics: diags,
	})
}

func (s *Server) sendResult(id json.RawMessage, result interface{}) error {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	payload, err := json.Marshal(RPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	})
	if err != nil {
		return err
	}
	return writeMessage(s.writer, &s.writeMu, payload)
}

func (s *Server) sendError(id json.RawMessage, code int, message string) error {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	// Omit result when error is set by using a local struct.
	type errResp struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Error   *RPCError       `json:"error"`
	}
	payload, err := json.Marshal(errResp{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &RPCError{Code: code, Message: message},
	})
	if err != nil {
		return err
	}
	return writeMessage(s.writer, &s.writeMu, payload)
}

func (s *Server) sendNotification(method string, params interface{}) error {
	payload, err := json.Marshal(RPCNotification{
		JSONRPC: "2.0",
		Method:  method,
		Params:  params,
	})
	if err != nil {
		return err
	}
	return writeMessage(s.writer, &s.writeMu, payload)
}
