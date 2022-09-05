package api

import (
	"bufio"
	"io/fs"
	"log"
	"os"
	"path"
	"path/filepath"

	"github.com/adedayo/checkmate-core/pkg/plugins"
)

func loadReportPlugins() (out []closableTransformer) {
	cwd := ""
	cwd, err := os.Getwd()
	if err != nil {
		cwd = ""
	}
	pluginsDir := path.Join(cwd, "plugins")
	_ = filepath.WalkDir(pluginsDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if match, err := filepath.Match("*_plugin", d.Name()); err == nil && match {
			plug, stdout, err := plugins.NewDiagnosticTransformerPlugin(path)

			if err != nil {
				log.Printf("Error instantiating plugin: %v", err)
				return nil
			}

			//stream stdout
			go func() {
				scanner := bufio.NewScanner(stdout)
				name := d.Name()
				for scanner.Scan() {
					log.Printf("\t (%s)> %s\n", name, scanner.Text())
				}
			}()
			out = append(out, closableTransformer{
				Plugin: plug,
			})
		}
		return nil
	})

	return
}
