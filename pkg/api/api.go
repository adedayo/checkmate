package api

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	common "github.com/adedayo/checkmate-core/pkg"
	"github.com/adedayo/checkmate-core/pkg/diagnostics"
	secrets "github.com/adedayo/checkmate-plugin/secrets-finder/pkg"
	"github.com/gorilla/mux"
)

var (
	routes = mux.NewRouter()
)

func init() {
	addRoutes()
}

func addRoutes() {
	routes.HandleFunc("/api/findsecrets", findSecrets).Methods("POST")
}

func findSecrets(w http.ResponseWriter, r *http.Request) {
	var data common.DataToScan
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if data.Base64 {
		b, err := base64.StdEncoding.DecodeString(data.Source)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		data.Source = string(b)
	}

	path := "" //dummy path
	options := secrets.SecretSearchOptions{
		Exclusions: diagnostics.MakeEmptyExcludes(),
	}
	finder := secrets.GetFinderForFileType(data.SourceType, path, options)
	diagnostics := []diagnostics.SecurityDiagnostic{}
	for diagnostic := range secrets.FindSecret(path, strings.NewReader(data.Source), finder, true) {
		diagnostics = append(diagnostics, diagnostic)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(diagnostics)
}

//ServeAPI serves the analysis service on the specified port
func ServeAPI(port int) {
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", port), routes))
}
