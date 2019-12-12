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
	"os"
	"path/filepath"

	"github.com/adedayo/checkmate/pkg/common"
	"github.com/adedayo/checkmate/pkg/modules/secrets"
	"github.com/spf13/cobra"
)

var (
	showSource bool
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
}

func search(cmd *cobra.Command, args []string) {
	directoryOrFile := make(map[string]bool)
	worklist := make(map[string]struct{})
	for _, arg := range args {
		path := filepath.Clean(arg)
		if fileInfo, err := os.Stat(path); !os.IsNotExist(err) {
			directoryOrFile[path] = fileInfo.IsDir()
		}
	}

	var nothing struct{}
	//collect unique files to analyse
	for file, isDir := range directoryOrFile {
		if isDir {
			for _, f := range getFiles(file) {
				println("Adding ", f)
				worklist[f] = nothing
			}
		} else {
			worklist[file] = nothing
		}
	}

	for file := range worklist {
		processFile(file)
	}

}

func processFile(path string) {
	if f, err := os.Open(path); err == nil {
		for issue := range secrets.FindSecret(f, secrets.NewJavaFinder(), showSource) {
			issue.Location = &path
			if x, err := json.Marshal(issue); err == nil {
				fmt.Printf("\n%s\n", x)
			}
		}
		f.Close()
	}
}

func getFiles(dir string) (paths []string) {
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return filepath.SkipDir
		}
		if _, present := common.TextFileExtensions[filepath.Ext(path)]; present {
			paths = append(paths, path)
		}
		return nil
	})
	return
}
