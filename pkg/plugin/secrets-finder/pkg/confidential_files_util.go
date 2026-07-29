package secrets

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/adedayo/checkmate/pkg/core/diagnostics"
)

func checkConfidential(cfile confidentialFile) diagnostics.Evidence {
	evidence := diagnostics.Evidence{
		Description: cfile.why,
		Confidence:  diagnostics.Medium,
	}

	path := cfile.path
	ext := filepath.Ext(path)

	switch filepath.Base(path) {
	case "id_dsa", "id_rsa":
		return processCertificate(cfile)
	case "id_dsa.pub", "id_rsa.pub":
		evidence.Confidence = diagnostics.Info
		evidence.Description = "Warning! You may be sharing public SSH keys with your code"

	}

	//TODO add more extension to look into their content
	switch ext {
	case ".crt", ".cer", ".pem", ".key":
		return processCertificate(cfile)
	case ".p12", ".pfx":
		if cfile.isTest {
			evidence.Confidence = diagnostics.High
		} else {
			evidence.Confidence = diagnostics.Critical
		}
	default:

		// if file, err := os.Open(path); err == nil {
		// 	if data, err := io.ReadAll(file); err == nil {
		// 		log.Printf("Cert: %s\n", string(data))
		// 	}
		// }
	}

	return evidence
}

// see https://datatracker.ietf.org/doc/html/rfc7468#section-4
func processCertificate(cfile confidentialFile) diagnostics.Evidence {
	evidence := diagnostics.Evidence{
		Description: cfile.why,
		Confidence:  diagnostics.High,
	}
	path := cfile.path
	if file, err := os.Open(path); err == nil {
		if data, err := io.ReadAll(file); err == nil {
			cert := string(data)

			matches := certIdentifier.FindAllStringSubmatch(cert, -1)
			if matches == nil { // no match, just return the cautious determination based on file extension
				return evidence
			}

			for _, m := range matches {
				evidence.Description = fmt.Sprintf("Warning! You may be sharing confidential (%s) data with your code", m[1])
				certType := strings.ToLower(m[1])
				if strings.Contains(certType, "private") {
					if cfile.isTest {
						evidence.Confidence = diagnostics.High
					} else {
						evidence.Confidence = diagnostics.Critical
					}
					return evidence
				}
				if strings.Contains(certType, "public") {
					evidence.Confidence = diagnostics.Info
				}

			}
		}
	}
	return evidence
}

type confidentialFile struct {
	path   string
	why    string
	isTest bool
}
