package lsp

import (
	"github.com/adedayo/go-lsp/pkg/jsonrpc2"
	"github.com/adedayo/go-lsp/pkg/lsp"
)

var (
//TODO: Debug - remove
// f, _ = os.Create("debug_messages.txt")
)

//NewSecurityServer provides a properly initialized instance of the CheckMate LSP driver
func NewSecurityServer() *SecurityServer {
	server := &SecurityServer{}
	server.DefaultServer.Init(server)
	return server
}

//SecurityServer is an LSP driver for CheckMate security analysis
type SecurityServer struct {
	lsp.DefaultServer
}

//Default handles non-predefined calls to SecurityServer
func (ss *SecurityServer) Default(req *jsonrpc2.Request) {
	// f.WriteString("\nCalling Default on Security Server: " + req.Method + "\n")
}
