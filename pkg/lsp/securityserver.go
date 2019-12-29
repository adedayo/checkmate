package lsp

import (
	"encoding/json"
	"net/url"
	"os"

	"github.com/adedayo/checkmate/pkg/common/diagnostics"
	"github.com/adedayo/checkmate/pkg/modules/secrets"
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
		var params lsp.InitializeParams
		if err := json.Unmarshal([]byte(*req.Params), &params); err == nil {
			for _, wsf := range params.WorkspaceFolders {
				if u, err := url.Parse(string(wsf.URI)); err == nil {
					ss.workspacePaths = append(ss.workspacePaths, u.Path)
				}
			}

		} else {
		}

	case "initialized":
		params := make(map[string][]lsp.Diagnostic)
		for diagnostic := range secrets.SearchSecretsOnPaths(ss.workspacePaths, false, diagnostics.DefaultWhitelistProvider{}) {
			if issues, exist := params[*diagnostic.Location]; exist {
				issues = append(issues, convert(diagnostic))
				params[*diagnostic.Location] = issues
			} else {
				params[*diagnostic.Location] = []lsp.Diagnostic{convert(diagnostic)}
			}
		}

		for loc := range params {
			parameter := lsp.PublishDiagnosticsParams{
				URI:         code.DocumentURI(loc),
				Diagnostics: params[loc],
			}
			if notificationParams, err := json.Marshal(parameter); err == nil {
				ss.SendNotification("textDocument/publishDiagnostics", notificationParams)
			}
		}

	case "shutdown":
		//exit anyway on shutdown request
		os.Exit(0)
	default:
	}
}
