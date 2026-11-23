package lsp

import "encoding/json"

// LSP 3.17 diagnostic severity constants.
type DiagnosticSeverity int

const (
	SeverityError       DiagnosticSeverity = 1
	SeverityWarning     DiagnosticSeverity = 2
	SeverityInformation DiagnosticSeverity = 3
	SeverityHint        DiagnosticSeverity = 4
)

// LSP TextDocumentSyncKind values.
const (
	TextDocumentSyncKindNone        = 0
	TextDocumentSyncKindFull        = 1
	TextDocumentSyncKindIncremental = 2
)

// Supported Quick Fix command identifiers.
const (
	CmdSuppressPathHash   = "checkmate.suppressPathHash"
	CmdSuppressGlobalHash = "checkmate.suppressGlobalHash"
	CmdExcludeFile        = "checkmate.excludeFile"
)

// Position is a 0-based line and character offset in a text document.
type Position struct {
	Line      int `json:"line"`
	Character int `json:"character"`
}

// Range is a half-open range in a text document.
type Range struct {
	Start Position `json:"start"`
	End   Position `json:"end"`
}

// DiagnosticData carries structured finding metadata attached to CheckMate LSP
// diagnostics so Code Actions can create precise hash/path suppressions without
// storing plaintext secret values.
type DiagnosticData struct {
	FindingID      string `json:"findingId"`
	SecretChecksum string `json:"secretChecksum,omitempty"`
	RuleID         string `json:"ruleId"`
}

// Diagnostic represents an LSP 3.17 diagnostic.
type Diagnostic struct {
	Range    Range              `json:"range"`
	Severity DiagnosticSeverity `json:"severity,omitempty"`
	Code     string             `json:"code,omitempty"`
	Source   string             `json:"source,omitempty"`
	Message  string             `json:"message"`
	Data     *DiagnosticData    `json:"data,omitempty"`
}

// PublishDiagnosticsParams is sent with textDocument/publishDiagnostics.
type PublishDiagnosticsParams struct {
	URI         string       `json:"uri"`
	Version     *int         `json:"version,omitempty"`
	Diagnostics []Diagnostic `json:"diagnostics"`
}

// WorkspaceFolder describes a root folder opened in the client editor.
type WorkspaceFolder struct {
	URI  string `json:"uri"`
	Name string `json:"name"`
}

// InitializeParams is received on initialize.
type InitializeParams struct {
	ProcessID        *int              `json:"processId,omitempty"`
	RootPath         string            `json:"rootPath,omitempty"`
	RootURI          string            `json:"rootUri,omitempty"`
	WorkspaceFolders []WorkspaceFolder `json:"workspaceFolders,omitempty"`
}

// SaveOptions configures textDocument/didSave notifications.
type SaveOptions struct {
	IncludeText bool `json:"includeText,omitempty"`
}

// TextDocumentSyncOptions describes how the server syncs document edits.
type TextDocumentSyncOptions struct {
	OpenClose bool         `json:"openClose,omitempty"`
	Change    int          `json:"change,omitempty"`
	Save      *SaveOptions `json:"save,omitempty"`
}

// CodeActionOptions advertises supported Code Action kinds.
type CodeActionOptions struct {
	CodeActionKinds []string `json:"codeActionKinds,omitempty"`
}

// ExecuteCommandOptions advertises supported workspace/executeCommand names.
type ExecuteCommandOptions struct {
	Commands []string `json:"commands"`
}

// WorkspaceFoldersServerCapabilities advertises workspace folder support.
type WorkspaceFoldersServerCapabilities struct {
	Supported           bool `json:"supported,omitempty"`
	ChangeNotifications bool `json:"changeNotifications,omitempty"`
}

// WorkspaceServerCapabilities groups workspace-level capabilities.
type WorkspaceServerCapabilities struct {
	WorkspaceFolders *WorkspaceFoldersServerCapabilities `json:"workspaceFolders,omitempty"`
}

// ServerCapabilities advertises CheckMate's LSP 3.17 capabilities.
type ServerCapabilities struct {
	TextDocumentSync       *TextDocumentSyncOptions     `json:"textDocumentSync,omitempty"`
	CodeActionProvider     *CodeActionOptions           `json:"codeActionProvider,omitempty"`
	ExecuteCommandProvider *ExecuteCommandOptions       `json:"executeCommandProvider,omitempty"`
	Workspace              *WorkspaceServerCapabilities `json:"workspace,omitempty"`
}

// ServerInfo identifies the CheckMate LSP server.
type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

// InitializeResult is returned from initialize.
type InitializeResult struct {
	Capabilities ServerCapabilities `json:"capabilities"`
	ServerInfo   *ServerInfo        `json:"serverInfo,omitempty"`
}

// TextDocumentIdentifier identifies a document by URI.
type TextDocumentIdentifier struct {
	URI string `json:"uri"`
}

// VersionedTextDocumentIdentifier identifies a specific version of a document.
type VersionedTextDocumentIdentifier struct {
	URI     string `json:"uri"`
	Version int    `json:"version"`
}

// TextDocumentItem represents an opened document with full contents.
type TextDocumentItem struct {
	URI        string `json:"uri"`
	LanguageID string `json:"languageId"`
	Version    int    `json:"version"`
	Text       string `json:"text"`
}

// TextDocumentContentChangeEvent describes a document edit.
type TextDocumentContentChangeEvent struct {
	Text string `json:"text"`
}

// DidOpenTextDocumentParams is received on textDocument/didOpen.
type DidOpenTextDocumentParams struct {
	TextDocument TextDocumentItem `json:"textDocument"`
}

// DidChangeTextDocumentParams is received on textDocument/didChange.
type DidChangeTextDocumentParams struct {
	TextDocument   VersionedTextDocumentIdentifier  `json:"textDocument"`
	ContentChanges []TextDocumentContentChangeEvent `json:"contentChanges"`
}

// DidSaveTextDocumentParams is received on textDocument/didSave.
type DidSaveTextDocumentParams struct {
	TextDocument TextDocumentIdentifier `json:"textDocument"`
	Text         *string                `json:"text,omitempty"`
}

// DidCloseTextDocumentParams is received on textDocument/didClose.
type DidCloseTextDocumentParams struct {
	TextDocument TextDocumentIdentifier `json:"textDocument"`
}

// FileEvent represents a file system event from workspace/didChangeWatchedFiles.
type FileEvent struct {
	URI  string `json:"uri"`
	Type int    `json:"type"`
}

// DidChangeWatchedFilesParams is received on workspace/didChangeWatchedFiles.
type DidChangeWatchedFilesParams struct {
	Changes []FileEvent `json:"changes"`
}

// WorkspaceFoldersChangeEvent describes added/removed workspace folders.
type WorkspaceFoldersChangeEvent struct {
	Added   []WorkspaceFolder `json:"added"`
	Removed []WorkspaceFolder `json:"removed"`
}

// DidChangeWorkspaceFoldersParams is received on workspace/didChangeWorkspaceFolders.
type DidChangeWorkspaceFoldersParams struct {
	Event WorkspaceFoldersChangeEvent `json:"event"`
}

// CodeActionContext carries diagnostics overlapping the requested range.
type CodeActionContext struct {
	Diagnostics []Diagnostic `json:"diagnostics"`
	Only        []string     `json:"only,omitempty"`
}

// CodeActionParams is received on textDocument/codeAction.
type CodeActionParams struct {
	TextDocument TextDocumentIdentifier `json:"textDocument"`
	Range        Range                  `json:"range"`
	Context      CodeActionContext      `json:"context"`
}

// Command represents an executable LSP command.
type Command struct {
	Title     string        `json:"title"`
	Command   string        `json:"command"`
	Arguments []interface{} `json:"arguments,omitempty"`
}

// CodeAction represents a Quick Fix returned by textDocument/codeAction.
type CodeAction struct {
	Title       string       `json:"title"`
	Kind        string       `json:"kind,omitempty"`
	Diagnostics []Diagnostic `json:"diagnostics,omitempty"`
	Command     *Command     `json:"command,omitempty"`
}

// ExecuteCommandParams is received on workspace/executeCommand.
type ExecuteCommandParams struct {
	Command   string            `json:"command"`
	Arguments []json.RawMessage `json:"arguments,omitempty"`
}
