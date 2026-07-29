package api

import (
	"fmt"
	"log"
	"net/http"

	gitutils "github.com/adedayo/checkmate/pkg/core/git"

	"github.com/gorilla/handlers"
)

var (
	configManager gitutils.GitConfigManager
)

//ServeAPI serves the analysis service on the specified port
func ServeAPI(config Config) {

	hostPort := "localhost:%d"
	if !config.Local {
		// not localhost electron app
		hostPort = ":%d"
	}

	corsOptions = append(corsOptions, handlers.AllowedOrigins(allowedOrigins))
	log.Printf("Running Git Service API on %s", fmt.Sprintf(hostPort, config.ApiPort))
	log.Fatal(http.ListenAndServe(fmt.Sprintf(hostPort, config.ApiPort), handlers.CORS(corsOptions...)(getRoutes(config.ProjectManager))))
}
