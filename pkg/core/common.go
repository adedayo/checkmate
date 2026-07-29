package common

import (
	"path/filepath"
	"strings"
	"sync"

	"github.com/adedayo/checkmate/pkg/core/diagnostics"
	"github.com/adedayo/checkmate/pkg/core/util"
)

//IsConfidentialFile indicates whether a file is potentially confidential based on its name or extension, with a narrative indicating
//what sort of file it may be if it is potentially confidential
func IsConfidentialFile(path string) (bool, string) {
	extension := filepath.Ext(path)
	baseName := strings.TrimSuffix(filepath.Base(path), extension)
	if narrative, present := DangerousFileNames[baseName]; present {
		return present, narrative
	}

	if narrative, present := CertsAndKeyStores[extension]; present {
		return present, narrative
	}

	if narrative, present := DangerousExtensions[extension]; present {
		return present, narrative
	}

	if narrative, present := FinancialAndAccountingExtensions[extension]; present && !excludeName(baseName) {
		return present, narrative
	}

	return false, ""
}

func excludeName(basname string) bool {
	switch strings.ToLower(basname) {
	case "readme", "changelog":
		return true
	}
	return false
}

//GetSensitiveFilesDescriptors gets all registered sensitive file descriptions
func GetSensitiveFilesDescriptors() []SensitiveFile {

	length := len(DangerousExtensions) + len(CertsAndKeyStores) + len(DangerousExtensions) +
		len(FinancialAndAccountingExtensions) + 2 //excluded 2 types
	files := make([]SensitiveFile, 0, length)
	for file, description := range DangerousFileNames {
		files = append(files, SensitiveFile{
			Extension:   file,
			Description: description,
		})
	}

	for ext, description := range CertsAndKeyStores {
		files = append(files, SensitiveFile{
			Extension:   ext,
			Description: description,
		})
	}

	for ext, description := range DangerousExtensions {
		files = append(files, SensitiveFile{
			Extension:   ext,
			Description: description,
		})
	}

	for ext, description := range FinancialAndAccountingExtensions {
		files = append(files, SensitiveFile{
			Extension:   ext,
			Description: description,
		})
	}

	files = append(files, SensitiveFile{
		Extension:   "readme[.].*",
		Description: "Readme files are usually non-sensitive",
		Excluded:    true,
	})

	files = append(files, SensitiveFile{
		Extension:   "changelog[.].*",
		Description: "Changelog files are usually non-sensitive",
		Excluded:    true,
	})

	return files
}

//SensitiveFile is a description of a potentially sensitive file based on its name or extension
type SensitiveFile struct {
	//if the value does not start with a . then filename is intended
	Extension   string
	Description string
	Excluded    bool //flag to indicate that this extension or filename should be ignored as non-sensitive
}

func appendMaps(maps ...map[string]string) map[string]string {
	result := make(map[string]string)
	for _, m := range maps {
		for k := range m {
			if v, present := result[k]; present {
				data := []string{}
				if strings.TrimSpace(m[k]) != "" {
					data = append(data, m[k])
				}
				if strings.TrimSpace(v) != "" {
					data = append(data, v)
				}
				result[k] = strings.Join(data, " or ")
			} else {
				result[k] = m[k]
			}
		}
	}
	return result
}

func makeMap(elements string) map[string]string {
	result := make(map[string]string)
	var nothing string
	for _, s := range strings.Split(elements, ",") {
		result["."+s] = nothing
	}
	return result
}

//SourceToSecurityDiagnostics is an interface that describes an object that can consume source and generates security diagnostics
type SourceToSecurityDiagnostics interface {
	util.ResourceConsumer
	diagnostics.SecurityDiagnosticsProvider
}

//PathToSecurityDiagnostics is an interface that describes an object that can consume a file path or URI and generates security diagnostics
type PathToSecurityDiagnostics interface {
	util.PathConsumer
	diagnostics.SecurityDiagnosticsProvider
}

//ResourceToSecurityDiagnostics is an interface that describes an object that consumes arbitrary resource and generates security diagnostics
type ResourceToSecurityDiagnostics interface {
	util.ResourceConsumer
	util.PathConsumer
	diagnostics.SecurityDiagnosticsProvider
}

//RegisterDiagnosticsConsumer registers a callback to consume diagnostics
func RegisterDiagnosticsConsumer(callback func(d *diagnostics.SecurityDiagnostic), providers ...diagnostics.SecurityDiagnosticsProvider) {
	consumer := c{
		callback: callback,
	}
	for _, p := range providers {
		p.AddConsumers(consumer)
	}
}

type c struct {
	callback func(d *diagnostics.SecurityDiagnostic)
}

func (n c) ReceiveDiagnostic(diagnostic *diagnostics.SecurityDiagnostic) {
	n.callback(diagnostic)
}

//DiagnosticsAggregator implements a strategy for aggregating diagnostics, e.g. removing duplicates, overlap, less sever issues etc.
type DiagnosticsAggregator interface {
	AddDiagnostic(diagnostic *diagnostics.SecurityDiagnostic)
	Aggregate() []*diagnostics.SecurityDiagnostic //Called when aggregation strategy is required to be run
}

type simpleDiagnosticAggregator struct {
	// input       chan diagnostics.SecurityDiagnostic
	// diagnostics            []*diagnostics.SecurityDiagnostic
	mutex                  sync.RWMutex
	fileIndexedDiagnostics map[string][]*diagnostics.SecurityDiagnostic
}

func (sda *simpleDiagnosticAggregator) AddDiagnostic(diagnostic *diagnostics.SecurityDiagnostic) {
	// sda.diagnostics = append(sda.diagnostics, diagnostic)
	file := ""
	if diagnostic.Location != nil {
		file = *diagnostic.Location
	}
	sda.mutex.Lock()
	if diags, present := sda.fileIndexedDiagnostics[file]; present {
		sda.fileIndexedDiagnostics[file] = append(diags, diagnostic)
	} else {
		sda.fileIndexedDiagnostics[file] = []*diagnostics.SecurityDiagnostic{diagnostic}
	}
	sda.mutex.Unlock()
}

func (sda *simpleDiagnosticAggregator) Aggregate() (agg []*diagnostics.SecurityDiagnostic) {
	for _, issues := range sda.fileIndexedDiagnostics {
		agg = append(agg, removeOverlappingIssues(issues)...)
	}
	return
}

func removeOverlappingIssues(issues []*diagnostics.SecurityDiagnostic) []*diagnostics.SecurityDiagnostic {
	excluded := make([]bool, len(issues))
	out := make([]*diagnostics.SecurityDiagnostic, 0)
	diagnostics := issues
	for i, di := range diagnostics {
		for j, dj := range diagnostics {
			if j != i {
				if dj.RawRange.Contains(&di.RawRange) &&
					di.Justification.Headline.Confidence <= dj.Justification.Headline.Confidence &&
					!di.RawRange.Contains(&dj.RawRange) {
					excluded[i] = true
					break
				}
			}
		}
	}

	for i, di := range diagnostics {
		if !excluded[i] {
			out = append(out, di)
		}
	}

	return out
}

//MakeSimpleAggregator creates a diagnostics aggregator that removes diagnostics whose range is completely
//overlapped by another diagnostic's range
func MakeSimpleAggregator() DiagnosticsAggregator {
	return &simpleDiagnosticAggregator{
		// diagnostics:            make([]*diagnostics.SecurityDiagnostic, 0),
		mutex:                  sync.RWMutex{},
		fileIndexedDiagnostics: make(map[string][]*diagnostics.SecurityDiagnostic),
	}
}
