package plugins

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/adedayo/checkmate/pkg/core/diagnostics"
)

func getFreePort() (port int, err error) {
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		return
	}

	ltcp, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return
	}
	defer func() {
		_ = ltcp.Close()
	}()
	port = ltcp.Addr().(*net.TCPAddr).Port
	return
}

func RegisterDiagnosticTransformer(transformer DiagnosticTransformer) (micro MicroService, err error) {

	port, err := getFreePort()
	if err != nil {
		return
	}
	fmt.Printf("port:%d\n", port)
	_ = os.Stdout.Sync()
	micro.Port = port
	mux := makeHandler(transformer)

	server := &http.Server{
		Addr:         fmt.Sprintf("localhost:%d", port),
		Handler:      mux,
		IdleTimeout:  120 * time.Second,
		ReadTimeout:  1 * time.Second,
		WriteTimeout: 1 * time.Second,
	}
	micro.HTTPServer = server

	return
}

func makeHandler(t DiagnosticTransformer) *http.ServeMux {
	mux := http.NewServeMux()
	dth := diagnosticTransformHandler{
		transformer: t,
	}
	mux.HandleFunc("/transform", cors(dth.transfromDiagnostics))
	return mux
}

func cors(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*") //OK, since we are bound to localhost
		next(w, r)
	})
}

type diagnosticTransformHandler struct {
	transformer DiagnosticTransformer
}

func (dth diagnosticTransformHandler) transfromDiagnostics(w http.ResponseWriter, r *http.Request) {

	switch r.Method {
	case http.MethodPost:
		var confD ConfigDiagnostics
		err := json.NewDecoder(r.Body).Decode(&confD)
		if err != nil {
			log.Printf("Error decoding diagnostics during transform")
		}
		defer func() {
			_ = r.Body.Close()
		}()
		d := dth.transformer.Transform(confD.Config, confD.Diagnostics...)
		json.NewEncoder(w).Encode(d)

	default:
		http.Error(w, errors.New("Only POST method is supported, but got "+r.Method).Error(), http.StatusBadRequest)
		return
	}

}

type MicroService struct {
	Port       int
	HTTPServer *http.Server
	ch         chan os.Signal
}

//shut down server and service
func (m *MicroService) ShutDown() {
	m.HTTPServer.Shutdown(context.Background())
}

func (m *MicroService) Start() {
	go func() {
		m.HTTPServer.ListenAndServe()
	}()

	m.ch = make(chan os.Signal)
	signal.Notify(m.ch, os.Interrupt, os.Kill)
	s := <-m.ch
	log.Printf("Shutting Microservice down with signal %v", s)
}

type pluginRunner struct {
	path         string
	transformURL string
	cmd          *exec.Cmd
}

func (p pluginRunner) ShutDown() error {
	return p.cmd.Process.Signal(os.Interrupt)
}

// Transform implements DiagnosticTransformer
func (p pluginRunner) Transform(config *Config, diags ...*diagnostics.SecurityDiagnostic) []*diagnostics.SecurityDiagnostic {
	data, err := json.Marshal(ConfigDiagnostics{
		Config:      config,
		Diagnostics: diags,
	})
	if err != nil {
		log.Printf("Error marshalling diagnostics: %v", err)
		return diags //noop
	}

	resp, err := http.Post(p.transformURL, "application/json", bytes.NewBuffer(data))

	if err != nil {
		log.Printf("Error invoking microservice transform endpoint: %v", err)
		return diags //noop
	}

	defer resp.Body.Close()
	out := []*diagnostics.SecurityDiagnostic{}

	err = json.NewDecoder(resp.Body).Decode(&out)

	if err != nil {
		log.Printf("Error decoding diagnostics response: %v", err)
		return diags //noop
	}

	return out
}

// creates and runs a new diagnostic transformer plugin
func NewDiagnosticTransformerPlugin(path string) (DiagnosticTransformerPlugin, io.Reader, error) {
	runner := pluginRunner{
		path: path,
	}

	cmd := exec.Command(path)
	runner.cmd = cmd

	pr, pw := io.Pipe()

	outPipe, err := cmd.StdoutPipe()
	if err != nil {
		return runner, pr, err
	}

	scanner := bufio.NewScanner(outPipe)

	err = cmd.Start()
	if err != nil {
		return runner, pr, err
	}

	go func() {
		cmd.Wait()
	}()

	//read the first port:<number> output
	if scanner.Scan() {
		output := scanner.Text()
		p := strings.Split(output, ":")
		if len(p) != 2 {
			return runner, pr, fmt.Errorf("Expecting output 'port:<number>' but got '%s'", output)
		}

		port, err := strconv.Atoi(strings.TrimSpace(p[1]))
		if err != nil {
			return runner, pr, fmt.Errorf("Expecting port as a number but got '%s'", p[1])
		}
		runner.transformURL = fmt.Sprintf("http://localhost:%d/transform", port)
	}

	//stream the rest of the result
	go func() {
		for scanner.Scan() {
			pw.Write(scanner.Bytes())
		}
	}()

	return runner, pr, nil

}
