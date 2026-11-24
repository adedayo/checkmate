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
	"fmt"
	"os"

	common "github.com/adedayo/checkmate/pkg/core"
	"github.com/spf13/cobra"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/viper"
)

var (
	cfgFile    string
	appVersion = "0.0.0"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   common.AppName,
	Short: fmt.Sprintf("Prevent a breach. Use %s to find hard-coded secrets in code, configuration, logs and other files.", common.AppName),
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute(version string) {
	appVersion = version
	rootCmd.Long = fmt.Sprintf(`Prevent a breach. Use %s to find hard-coded secrets in code, configuration, logs and other files.

  Version: %s
  Author: Dr. Adedayo Adetoye (Dayo) <https://github.com/adedayo>

Quick Start:
  %s hook install                    Install as a Git pre-commit hook
  %s hook run                        Scan staged Git changes (fast, redacted, exit 1 on findings)
  %s search <path|url>               Scan local files, directories, or Git repositories
  %s describe                        Machine-readable CLI manifest for AI agents (--format json|markdown)
  %s mcp serve --ephemeral           Start an MCP server for AI coding agents
`, common.AppName, version, common.AppName, common.AppName, common.AppName, common.AppName, common.AppName)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", fmt.Sprintf("config file (default is $HOME/.%s.yaml)", common.AppName))
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		// Search config in home directory with name ".checkmate" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigName(fmt.Sprintf(".%s", common.AppName))
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	// Log to stderr so stdio protocol commands (mcp serve, lspServe) keep stdout clean.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}
