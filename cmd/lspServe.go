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
	"io/ioutil"
	"log"
	"os"

	"github.com/adedayo/checkmate-core/pkg/diagnostics"
	"github.com/adedayo/checkmate/pkg/lsp"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var (
	allowedOrigins = []string{}
	lspExclusions  string
)

const (
	//headerLengthPrefix is the content length preamble
	headerLengthPrefix = "Content-Length:"
)

// lspServeCmd represents the lspServe command
var lspServeCmd = &cobra.Command{
	Use:   "lspServe",
	Short: "Drive code security analysis using the Language Server Protocol",
	Long:  `Drive code security analysis using the Language Server Protocol`,
	Run: func(cmd *cobra.Command, args []string) {
		var wld diagnostics.ExcludeDefinition
		if lspExclusions != "" {
			data, err := ioutil.ReadFile(lspExclusions)
			if err != nil {
				log.Printf("Warning: %s. Continuing with no exclusion", err.Error())
			} else {
				if err := yaml.Unmarshal(data, &wld); err != nil {
					log.Printf("Warning: %s. Continuing with no exclusion", err.Error())
				}
			}
		}
		var wl diagnostics.ExclusionProvider
		if w, err := diagnostics.CompileExcludes(&wld); err != nil {
			log.Printf("Warning: %s. Continuing with no exclusion", err.Error())
		} else {
			wl = w
		}
		server := lsp.NewSecurityServer(wl)
		server.Start(os.Stdin, os.Stdout)
	},
}

func init() {
	rootCmd.AddCommand(lspServeCmd)
	lspServeCmd.Flags().StringVarP(&lspExclusions, "exclusion", "w", "", "Use provided exclusion yaml configuration")
}
