package api

import (
	"context"
	"fmt"
	"sync"

	"github.com/adedayo/checkmate-core/pkg/diagnostics"
	"github.com/adedayo/checkmate-core/pkg/projects"
	secrets "github.com/adedayo/checkmate-plugin/secrets-finder/pkg"
	"github.com/adedayo/checkmate/pkg/reports/asciidoc"
	"github.com/gorilla/websocket"
)

var (
	sockets = make(map[string][]*websocket.Conn)
	socLock sync.RWMutex
)

func addScanListener(socketIndex string, ws *websocket.Conn) {
	socLock.Lock()
	defer socLock.Unlock()
	if conns, exists := sockets[socketIndex]; exists {
		sockets[socketIndex] = append(conns, ws)
	} else {
		sockets[socketIndex] = []*websocket.Conn{ws}
	}
}

func removeScanListeners(socketIndex string) {
	socLock.Lock()
	defer socLock.Unlock()
	if conns, exists := sockets[socketIndex]; exists {
		msg := "Scan Completed: " + socketIndex
		for _, ws := range conns {
			ws.WriteJSON(SocketEndMessage{msg})
			ws.Close()
		}
		delete(sockets, socketIndex)
	}
}

func runSecretScan(ctx context.Context, options ProjectScanOptions, ws *websocket.Conn) {

	project := pm.GetProject(options.ProjectID)
	if project.ID == options.ProjectID {
		id := makeID(options.ProjectID, "")

		consumer := webSocketDiagnosticConsumer{
			buff: []*diagnostics.SecurityDiagnostic{},
		}

		scanIDC := func(sID string) {
			options.ScanID = sID
			id = makeID(options.ProjectID, options.ScanID)
			addScanListener(id, ws)
			consumer.start(id)
		}

		paths := []string{}
		progressMon := func(progress diagnostics.Progress) {
			paths = append(paths, progress.CurrentFile)
			for _, ws := range getListeningSockets(id) {
				ws.WriteJSON(progress)
			}
		}

		secOptions := secrets.SecretSearchOptions{
			ShowSource:        true,
			CalculateChecksum: true,
			Exclusions:        diagnostics.MakeEmptyExcludes(),
		}

		if options, ok := project.ScanPolicy.Config["secret-search-options"]; ok {
			if scanOpts, good := options.(secrets.SecretSearchOptions); good {
				secOptions = scanOpts
				excludes := secrets.MergeExclusions(project.ScanPolicy.Policy, secrets.MakeCommonExclusions())
				container := diagnostics.ExcludeContainer{
					ExcludeDef: &excludes,
				}
				for _, loc := range project.Repositories {
					container.Repositories = append(container.Repositories, loc.Location)
				}
				if excl, err := diagnostics.CompileExcludes(container); err == nil {
					secOptions.Exclusions = excl
				}
			}
		}

		summariser := func(projID, sID string, issues []*diagnostics.SecurityDiagnostic) *projects.ScanSummary {

			model, err := asciidoc.ComputeMetrics(len(paths), secOptions.ShowSource, issues)
			if err != nil {
				return &projects.ScanSummary{}
			}
			summary := model.Summarise()
			project = pm.GetProject(options.ProjectID) //reloading project as policies might have been manually changed during scanning
			ws.WriteJSON(project)
			ws.WriteJSON(summary)
			removeScanListeners(id)
			return summary
		}

		pm.RunScan(ctx, project.ID, project.ScanPolicy, secrets.MakeSecretScanner(secOptions), scanIDC, progressMon, summariser, workspaceSummariser, &consumer)
	}
}

type webSocketDiagnosticConsumer struct {
	id      string
	started bool
	buff    []*diagnostics.SecurityDiagnostic
}

func (c *webSocketDiagnosticConsumer) start(id string) {
	c.id = id
	c.started = true
	for _, ws := range getListeningSockets(c.id) {
		for _, diagnostic := range c.buff {
			ws.WriteJSON(diagnostic)
		}
	}
	c.buff = []*diagnostics.SecurityDiagnostic{}
}

func (c *webSocketDiagnosticConsumer) ReceiveDiagnostic(diagnostic *diagnostics.SecurityDiagnostic) {

	if c.started {
		for _, ws := range getListeningSockets(c.id) {
			ws.WriteJSON(diagnostic)
		}
	} else {
		c.buff = append(c.buff, diagnostic)
	}

}

func makeID(projectID, scanID string) string {
	return fmt.Sprintf("%s:%s", projectID, scanID)
}

func getListeningSockets(id string) (s []*websocket.Conn) {
	socLock.RLock()
	defer socLock.RUnlock()
	if conns, exists := sockets[id]; exists {
		return conns
	}
	return
}
