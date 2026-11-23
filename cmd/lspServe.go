package cmd

/*
Copyright © 2019 Adedayo Adetoye (aka Dayo)
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
   may be used to endorse or promote products derived from this software
   without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
*/

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	common "github.com/adedayo/checkmate/pkg/core"
	"github.com/adedayo/checkmate/pkg/lsp"
	"github.com/adedayo/checkmate/pkg/store"
	"github.com/adedayo/checkmate/pkg/store/sqlite"
	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
)

var (
	lspExclusions      string
	lspDataPath        string
	lspNoDB            bool
	lspNoWorkspaceScan bool
)

// lspServeCmd represents the lspServe command
var lspServeCmd = &cobra.Command{
	Use:   "lspServe",
	Short: "Drive code security analysis using the Language Server Protocol",
	Long:  `Starts CheckMate as an LSP 3.17 Language Server over stdin/stdout for real-time in-editor secret detection and Quick Fix suppressions.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Keep stdout strictly reserved for Content-Length framed JSON-RPC messages.
		log.SetOutput(os.Stderr)

		var dbStore store.PlatformStore
		if !lspNoDB {
			expanded, err := homedir.Expand(lspDataPath)
			if err != nil {
				log.Printf("Warning: cannot expand data path %s: %v. Running without SQLite exceptions.", lspDataPath, err)
			} else if db, err := sqlite.New(expanded); err != nil {
				log.Printf("Warning: cannot open SQLite store at %s: %v. Running without SQLite exceptions.", expanded, err)
			} else {
				dbStore = db
				defer func() { _ = db.Close() }()
			}
		}

		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()

		server := lsp.NewServer(lsp.ServerOptions{
			ExclusionFile:        lspExclusions,
			Store:                dbStore,
			DisableWorkspaceScan: lspNoWorkspaceScan,
			Version:              appVersion,
		})
		code, err := server.Serve(ctx, os.Stdin, os.Stdout)
		if err != nil && err != context.Canceled {
			log.Printf("LSP server error: %v", err)
		}
		if code != 0 {
			os.Exit(code)
		}
	},
}

func init() {
	rootCmd.AddCommand(lspServeCmd)
	lspServeCmd.Flags().StringVarP(&lspExclusions, "exclusion", "w", "", "Use provided exclusion yaml configuration")
	lspServeCmd.Flags().StringVar(&lspDataPath, "data-path", "~/.checkmate", fmt.Sprintf("Location of %s data and SQLite database for shared exceptions", common.AppDisplayName))
	lspServeCmd.Flags().BoolVar(&lspNoDB, "no-db", false, "Disable reading and writing shared SQLite exceptions (persist Quick Fixes to workspace .checkmate.yaml instead)")
	lspServeCmd.Flags().BoolVar(&lspNoWorkspaceScan, "no-workspace-scan", false, "Skip automatic background workspace scan on initialized")
}
