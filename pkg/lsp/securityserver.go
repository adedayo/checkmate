package lsp

import (
	"encoding/json"
	"net/url"
	"os"
	"path"
	"strings"

	core "github.com/adedayo/checkmate-core/pkg/diagnostics"
	secrets "github.com/adedayo/checkmate-plugin/secrets-finder/pkg"

	"github.com/adedayo/go-lsp/pkg/code"
	"github.com/adedayo/go-lsp/pkg/jsonrpc2"
	"github.com/adedayo/go-lsp/pkg/lsp"
)

//NewSecurityServer provides a properly initialized instance of the CheckMate LSP driver
func NewSecurityServer() lsp.Server {
	server := &SecurityServer{}
	server.DefaultServer.Init(server)
	return server
}

//SecurityServer is an LSP driver for CheckMate security analysis
type SecurityServer struct {
	lsp.DefaultServer
	workspacePaths []string
}

//Default handles non-predefined calls to SecurityServer
func (ss *SecurityServer) Default(req *jsonrpc2.Request) {
	switch req.Method {
	case "initialize":
		ss.initWorkspace(req)
	case "initialized":
		ss.analyseWorkspace()
	case "shutdown":
		//exit anyway on shutdown request
		os.Exit(0)
	case "textDocument/didOpen":
		ss.didOpen(req)
	case "textDocument/didChange":
		ss.didChange(req)
	default:
	}
}

func (ss *SecurityServer) initWorkspace(req *jsonrpc2.Request) {
	var params lsp.InitializeParams
	if err := json.Unmarshal([]byte(*req.Params), &params); err == nil {
		for _, wsf := range params.WorkspaceFolders {
			if u, err := url.Parse(string(wsf.URI)); err == nil {
				ss.workspacePaths = append(ss.workspacePaths, u.Path)
			}
		}
	}
}

func (ss *SecurityServer) analyseWorkspace() {
	params := make(map[string][]lsp.Diagnostic)
	issues, paths := secrets.SearchSecretsOnPaths(ss.workspacePaths, false, core.MakeEmptyWhitelists())
	for diagnostic := range issues {
		if issues, exist := params[*diagnostic.Location]; exist {
			issues = append(issues, convert(diagnostic))
			params[*diagnostic.Location] = issues
		} else {
			params[*diagnostic.Location] = []lsp.Diagnostic{convert(diagnostic)}
		}
	}
	<-paths

	for loc := range params {
		parameter := lsp.PublishDiagnosticsParams{
			URI:         code.DocumentURI(loc),
			Diagnostics: params[loc],
		}
		ss.SendNotification("textDocument/publishDiagnostics", parameter)
	}
}

func (ss *SecurityServer) didOpen(req *jsonrpc2.Request) {
	var params lsp.DidOpenTextDocumentParams
	if err := json.Unmarshal([]byte(*req.Params), &params); err == nil {
		text := params.TextDocument.Text
		sourceType := path.Ext(string(params.TextDocument.URI))
		finder := secrets.GetFinderForFileType(sourceType)
		issues := []lsp.Diagnostic{}
		for diagnostic := range secrets.FindSecret(strings.NewReader(text), finder, false) {
			issues = append(issues, convert(diagnostic))
		}

		parameter := lsp.PublishDiagnosticsParams{
			URI:         params.TextDocument.URI,
			Diagnostics: issues,
		}
		ss.SendNotification("textDocument/publishDiagnostics", parameter)
	}
}

func (ss *SecurityServer) didChange(req *jsonrpc2.Request) {
	var params lsp.DidChangeTextDocumentParams
	if err := json.Unmarshal([]byte(*req.Params), &params); err == nil {
		if length := len(params.ContentChanges); length > 0 {
			text := params.ContentChanges[length-1].Text
			sourceType := path.Ext(string(params.TextDocument.URI))
			finder := secrets.GetFinderForFileType(sourceType)
			issues := []lsp.Diagnostic{}
			for diagnostic := range secrets.FindSecret(strings.NewReader(text), finder, false) {
				issues = append(issues, convert(diagnostic))
			}

			parameter := lsp.PublishDiagnosticsParams{
				URI:         params.TextDocument.URI,
				Diagnostics: issues,
			}
			ss.SendNotification("textDocument/publishDiagnostics", parameter)
		}

	}

}
