package cmd

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	common "github.com/adedayo/checkmate/pkg/core"
	"github.com/adedayo/checkmate/pkg/mcp"
	"github.com/adedayo/checkmate/pkg/store/sqlite"
	"github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
)

var (
	mcpDataPath  string
	mcpEphemeral bool
)

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Model Context Protocol (MCP) server for AI agent integration",
	Long:  `Expose CheckMate scanning, clustering, false-positive suppression, and sanitised reporting to AI agents via MCP.`,
}

var mcpServeCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start CheckMate MCP server over stdio",
	Long:  `Starts CheckMate as a Model Context Protocol (MCP) server using newline-delimited JSON-RPC 2.0 over stdin/stdout.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Ensure all standard log output goes to stderr so stdout stays strictly JSON-RPC.
		log.SetOutput(os.Stderr)

		dataDir := mcpDataPath
		var cleanup func()
		if mcpEphemeral {
			tmpDir, err := os.MkdirTemp("", "checkmate-mcp-*")
			if err != nil {
				return fmt.Errorf("create ephemeral data dir: %w", err)
			}
			dataDir = tmpDir
			cleanup = func() { _ = os.RemoveAll(tmpDir) }
		} else {
			expanded, err := homedir.Expand(dataDir)
			if err != nil {
				return fmt.Errorf("expand data path: %w", err)
			}
			dataDir = expanded
		}
		if cleanup != nil {
			defer cleanup()
		}

		db, err := sqlite.New(dataDir)
		if err != nil {
			return fmt.Errorf("open checkmate store at %s: %w", dataDir, err)
		}
		defer func() { _ = db.Close() }()

		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()

		srv := mcp.NewServer(db, appVersion)
		return srv.ServeStdio(ctx, os.Stdin, os.Stdout)
	},
}

func init() {
	rootCmd.AddCommand(mcpCmd)
	mcpCmd.AddCommand(mcpServeCmd)
	mcpServeCmd.Flags().StringVar(&mcpDataPath, "data-path", "~/.checkmate", fmt.Sprintf("Location of %s data and SQLite database", common.AppDisplayName))
	mcpServeCmd.Flags().BoolVar(&mcpEphemeral, "ephemeral", false, "Use a temporary SQLite store cleaned up on exit (ideal for one-shot CI/PR runs)")
}
