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
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var (
	paths bool
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
	// secretSearchCmd.Flags().IntVarP(&port, "port", "p", 8080, "Port on which to serve the API service")
	secretSearchCmd.Flags().BoolVarP(&paths, "paths", "p", false, "Indicate that the arguments are paths and search recursively for possible secrets in files contained all subdirectories of the paths")
}

func search(cmd *cobra.Command, args []string) {

	fmt.Printf("Got paths %#v, %t\n", args, paths)
	directoryOrFile := make(map[string]bool)
	for _, arg := range args {
		path := filepath.Clean(arg)
		if fileInfo, err := os.Stat(path); !os.IsNotExist(err) {
			directoryOrFile[path] = fileInfo.IsDir()
		}
	}

	for file, isDir := range directoryOrFile {
		if isDir {
			println(file)
		} else {

		}

	}
	// if file, err := os.Open("/Users/aadetoye/softdev/opensrc/java/static-analysis-test-code/src/main/java/com/github/adedayo/test/SecretsInCode.java"); err == nil {
	// 	shouldProvideSourceInDiagnostics := true
	// 	for issue := range secrets.FindSecret(file, secrets.NewJavaFinder(), shouldProvideSourceInDiagnostics) {
	// 		fmt.Printf("\nFound issue %+v, %s\n", issue, issue.Source)
	// 	}
	// 	file.Close()
	// }
}
