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

	common "github.com/adedayo/checkmate-core/pkg"
	"github.com/adedayo/checkmate/pkg/api"
	scheduler "github.com/adedayo/checkmate/pkg/cron"
	"github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
)

var (
	port, autoScanSchedule     int
	bindLocal, serveGitService bool
	cmDataPath                 string
)

// apiCmd represents the api command
var apiCmd = &cobra.Command{
	Use:   "api",
	Short: "Expose code security analysis as an API",
	Long:  `Expose code security analysis as an API`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf(`Running %s as an API service on port %d
		
Version: %s

Author: Adedayo Adetoye (Dayo) <https://github.com/adedayo>
		`, common.AppName, port, appVersion)

		cmDataPath, _ = homedir.Expand(cmDataPath)

		//run automated scheduled scans
		scheduleConfig := scheduler.Config{
			Frequency:        autoScanSchedule,
			DataDir:          cmDataPath,
			ScanOlderCommits: false, //TODO: make this configurable
		}
		go scheduler.ScheduleReposiroryTracking(scheduleConfig)

		//serve API
		config := api.Config{
			AppName:           common.AppName,
			AppVersion:        appVersion,
			ApiPort:           port,
			Local:             bindLocal,
			ServeGitService:   serveGitService,
			CheckMateDataPath: cmDataPath,
		}
		api.ServeAPI(config)
	},
}

func init() {
	rootCmd.AddCommand(apiCmd)
	apiCmd.Flags().IntVarP(&port, "port", "p", 17283, "Port on which to serve the API service")
	apiCmd.Flags().BoolVar(&bindLocal, "bind-localhost", false, "Bind the API service to localhost")
	apiCmd.Flags().IntVar(&autoScanSchedule, "auto-scanning-schedule", 300, "Time interval (in seconds) between launch of automatic scanning of monitored repository")
	apiCmd.Flags().BoolVar(&serveGitService, "serve-git-service", false, "Serve Git Service alongside the API")
	apiCmd.Flags().StringVar(&cmDataPath, "data-path", "~/.checkmate", fmt.Sprintf("Location of %s data and configurations", common.AppDisplayName))
}
