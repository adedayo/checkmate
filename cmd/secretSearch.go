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

	"github.com/adedayo/checkmate/pkg/common"
	"github.com/adedayo/checkmate/pkg/common/diagnostics"
	"github.com/adedayo/checkmate/pkg/modules/secrets"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var (
	showSource bool
	whitelist  string
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
}

func search(cmd *cobra.Command, args []string) {
	fmt.Printf("Starting %s %s (https://github.com/adedayo/checkmate)\n", common.AppName, appVersion)
	var wl diagnostics.DefaultWhitelistProvider
	if whitelist != "" {
		data, err := ioutil.ReadFile(whitelist)
		if err != nil {
			log.Printf("Warning: %s. Continuing with no whitelist", err.Error())
		} else {
			if err := yaml.Unmarshal(data, &wl); err != nil {
				log.Printf("Warning: %s. Continuing with no whitelist", err.Error())
			}
		}
		wl.CompileRegExs()
	}
	for issue := range secrets.SearchSecretsOnPaths(args, showSource, wl) {
		if x, err := json.Marshal(issue); err == nil {
			fmt.Printf("\n%s\n", x)
		}
	}

}
