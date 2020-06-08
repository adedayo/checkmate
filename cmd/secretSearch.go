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
package cmd

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"

	common "github.com/adedayo/checkmate-core/pkg"
	"github.com/adedayo/checkmate-core/pkg/diagnostics"
	secrets "github.com/adedayo/checkmate-plugin/secrets-finder/pkg"
	"github.com/adedayo/checkmate/pkg/reports/asciidoc"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var (
	showSource, asJSON bool
	whitelist          string
)

// secretSearchCmd represents the secretSearch command
var secretSearchCmd = &cobra.Command{
	Use:   "secretSearch",
	Short: "Search for secrets in a textual data source",
	Long:  `Search for secrets in a textual data source`,
	Run:   search,
}

func init() {
	rootCmd.AddCommand(secretSearchCmd)
	secretSearchCmd.Flags().BoolVarP(&showSource, "source", "s", false, "Provide source code evidence in the diagnostic results")
	secretSearchCmd.Flags().StringVarP(&whitelist, "whitelist", "w", "", "Use provided whitelist yaml configuration")
	secretSearchCmd.Flags().BoolVar(&asJSON, "json", false, "Generate JSON output")
}

func search(cmd *cobra.Command, args []string) {
	if !asJSON {
		fmt.Printf("Starting %s %s (https://github.com/adedayo/checkmate)\n", common.AppName, appVersion)
	}
	var wld diagnostics.WhitelistDefinition
	if whitelist != "" {
		data, err := ioutil.ReadFile(whitelist)
		if err != nil {
			log.Printf("Warning: %s. Continuing with no whitelist", err.Error())
		} else {
			if err := yaml.Unmarshal(data, &wld); err != nil {
				log.Printf("Warning: %s. Continuing with no whitelist", err.Error())
			}
		}
	}
	var wl diagnostics.WhitelistProvider
	if w, err := diagnostics.CompileWhitelists(&wld); err != nil {
		log.Printf("Warning: %s. Continuing with no whitelist", err.Error())
	} else {
		wl = w
	}
	issues := []diagnostics.SecurityDiagnostic{}
	issueChannel, paths := secrets.SearchSecretsOnPaths(args, showSource, wl)

	for issue := range issueChannel {
		issues = append(issues, issue)
		// if x, err := json.Marshal(issue); err == nil {
		// 	// fmt.Printf("\n%s\n", x)
		// }
	}
	files := <-paths
	// fmt.Printf("\n,Files: %#v\n", files)

	if asJSON {
		if x, err := json.MarshalIndent(issues, "", " "); err == nil {
			fmt.Printf("%s", x)
		} else {
			log.Printf("Marshall Error: %s", err.Error())
			fmt.Print("[]")
		}
	} else {
		path, err := asciidoc.GenerateReport(files, issues...)
		if err != nil {
			println("Error: ", err.Error())
			return
		}
		println("Report generated at ", path)
	}
}
