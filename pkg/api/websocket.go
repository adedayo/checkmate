package api

import (
	"context"
	"strings"
	"sync"

	"github.com/adedayo/checkmate-core/pkg/diagnostics"
	"github.com/adedayo/checkmate-core/pkg/projects"
	secrets "github.com/adedayo/checkmate-plugin/secrets-finder/pkg"
	"github.com/adedayo/checkmate/pkg/reports/asciidoc"
	"github.com/gorilla/websocket"
)

var (
	// sockets          = make(map[string][]*websocket.Conn)
	// socLock          sync.RWMutex
	longLivedSockets = make(map[string]map[string]*websocket.Conn) //projectID -> remoteAddres -> listening socket, they get removed when remote closes
	longSocLock      sync.RWMutex
)

func addLongLivedSocket(ctx context.Context, options MonitorOptions, ws *websocket.Conn) {
	longSocLock.Lock()
	defer longSocLock.Unlock()

	for _, projectID := range options.ProjectIDs {
		conns := make(map[string]*websocket.Conn)
		if cc, exists := longLivedSockets[projectID]; exists {
			conns = cc
		}
		remoteAdd := ws.RemoteAddr().String()
		conns[remoteAdd] = ws
		longLivedSockets[projectID] = conns
	}
	go cleanClose(ws)

}

func cleanClose(ws *websocket.Conn) {
	ws.SetCloseHandler(socketCloseHandler(ws))
	for {
		if _, _, err := ws.NextReader(); err != nil {
			ws.Close()
			break
		}
	}
}

func socketCloseHandler(ws *websocket.Conn) func(code int, text string) error {
	return func(code int, text string) error {
		longSocLock.Lock()
		defer longSocLock.Unlock()
		for projID, socks := range longLivedSockets {
			delete(socks, ws.RemoteAddr().String())
			longLivedSockets[projID] = socks
		}
		return nil
	}
}

// func addScanListener(socketIndex string, ws *websocket.Conn) {
// 	socLock.Lock()
// 	defer socLock.Unlock()
// 	if conns, exists := sockets[socketIndex]; exists {
// 		sockets[socketIndex] = append(conns, ws)
// 	} else {
// 		sockets[socketIndex] = []*websocket.Conn{ws}
// 	}
// }

// func removeScanListeners(socketIndex string) {
// 	socLock.Lock()
// 	defer socLock.Unlock()
// 	if conns, exists := sockets[socketIndex]; exists {
// 		msg := "Scan Completed: " + socketIndex
// 		for _, ws := range conns {
// 			ws.WriteJSON(SocketEndMessage{msg})
// 			ws.Close()
// 		}
// 		delete(sockets, socketIndex)
// 	}
// }

func runSecretScan(ctx context.Context, options ProjectScanOptions, ws *websocket.Conn) {

	project := pm.GetProject(options.ProjectID)
	if project.ID == options.ProjectID {
		id := options.ProjectID

		consumer := webSocketDiagnosticConsumer{
			buff: []*diagnostics.SecurityDiagnostic{},
		}

		//scanID consumer <- scanID is generated by the scanner
		scanIDC := func(sID string) {
			options.ScanID = sID
			// id = makeID(options.ProjectID, options.ScanID)
			addLongLivedSocket(ctx, MonitorOptions{ProjectIDs: []string{options.ProjectID}}, ws)
			// addScanListener(id, ws)
			consumer.start(options.ProjectID)
		}

		paths := []string{}
		progressMon := func(progress diagnostics.Progress) {
			paths = append(paths, progress.CurrentFile)
			for _, ws := range GetListeningSocketsByProjectID(id) {
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
			// removeScanListeners(id)
			return summary
		}

		pm.RunScan(ctx, project.ID, project.ScanPolicy, secrets.MakeSecretScanner(secOptions), scanIDC, progressMon, summariser, projects.SimpleWorkspaceSummariser, &consumer)
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

	// for _, ws := range getListeningSockets(c.id) {
	// 	for _, diagnostic := range c.buff {
	// 		ws.WriteJSON(diagnostic)
	// 	}
	// }
	// c.buff = []*diagnostics.SecurityDiagnostic{}
}

//Stop streaming diagnostics - noop
func (c *webSocketDiagnosticConsumer) ReceiveDiagnostic(diagnostic *diagnostics.SecurityDiagnostic) {

	// if c.started {
	// 	for _, ws := range getListeningSockets(c.id) {
	// 		ws.WriteJSON(diagnostic)
	// 	}
	// } else {
	// 	c.buff = append(c.buff, diagnostic)
	// }

}

// func makeID(projectID, scanID string) string {
// 	return fmt.Sprintf("%s:%s", projectID, scanID)
// }

// func getListeningSockets(id string) (s []*websocket.Conn) {
// 	longConns := getListeningSockets2(id)
// socLock.RLock()
// defer socLock.RUnlock()
// if conns, exists := sockets[id]; exists {
// 	out := append(longConns, conns...)
// 	log.Printf("Returning total of %d sockets", len(out))
// 	return out
// }
// return longConns
// }

func GetListeningSocketsByProjectID(id string) []*websocket.Conn {
	projID := strings.Split(id, ":")[0]
	longSocLock.Lock()
	defer longSocLock.Unlock()

	out := []*websocket.Conn{}
	if conns, exist := longLivedSockets[projID]; exist {
		for _, c := range conns {
			out = append(out, c)
		}
	}
	return out
}
