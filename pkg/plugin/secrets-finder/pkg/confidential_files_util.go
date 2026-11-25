package secrets

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	common "github.com/adedayo/checkmate/pkg/core"
	"github.com/adedayo/checkmate/pkg/core/diagnostics"
)

func checkConfidential(cfile confidentialFile) diagnostics.Evidence {
	return checkConfidentialWithContent(cfile, nil)
}

// CheckConfidentialBytes evaluates a confidential file path using already-loaded
// content bytes (for example, staged Git blobs or stdin) without reading from
// disk.
func CheckConfidentialBytes(path string, content []byte, isTest bool) (diagnostics.Evidence, bool) {
	confidential, why := common.IsConfidentialFile(path)
	if !confidential {
		return diagnostics.Evidence{}, false
	}
	return checkConfidentialWithContent(confidentialFile{
		path:   path,
		why:    fmt.Sprintf("Warning! You may be sharing confidential (%s) data with your code", why),
		isTest: isTest,
	}, content), true
}

func checkConfidentialWithContent(cfile confidentialFile, content []byte) diagnostics.Evidence {
	evidence := diagnostics.Evidence{
		Description: cfile.why,
		Confidence:  diagnostics.Medium,
	}

	path := cfile.path
	ext := strings.ToLower(filepath.Ext(path))

	switch filepath.Base(path) {
	case "id_dsa", "id_rsa", "id_ed25519", "id_ecdsa", "id_ed25519_sk", "id_ecdsa_sk":
		return processCertificateWithContent(cfile, content)
	case "id_dsa.pub", "id_rsa.pub", "id_ed25519.pub", "id_ecdsa.pub", "id_ed25519_sk.pub", "id_ecdsa_sk.pub":
		evidence.Confidence = diagnostics.Info
		evidence.Description = "Warning! You may be sharing public SSH keys with your code"
		return evidence
	}

	//TODO add more extension to look into their content
	switch ext {
	case ".crt", ".cer", ".pem", ".key":
		return processCertificateWithContent(cfile, content)
	case ".p12", ".pfx":
		if cfile.isTest {
			evidence.Confidence = diagnostics.High
		} else {
			evidence.Confidence = diagnostics.Critical
		}
	default:
	}

	return evidence
}

// see https://datatracker.ietf.org/doc/html/rfc7468#section-4
func processCertificateWithContent(cfile confidentialFile, content []byte) diagnostics.Evidence {
	evidence := diagnostics.Evidence{
		Description: cfile.why,
		Confidence:  diagnostics.High,
	}
	var data []byte
	if content != nil {
		data = content
	} else if file, err := os.Open(cfile.path); err == nil {
		defer func() { _ = file.Close() }()
		if read, err := io.ReadAll(file); err == nil {
			data = read
		}
	}
	if len(data) == 0 {
		return evidence
	}

	cert := string(data)
	matches := certIdentifier.FindAllStringSubmatch(cert, -1)
	if matches == nil { // no match, just return the cautious determination based on file extension
		return evidence
	}

	hasPublicOrCert := false
	lastLabel := ""
	for _, m := range matches {
		label := m[1]
		lastLabel = label
		certType := strings.ToLower(strings.TrimSpace(label))
		if strings.Contains(certType, "private") {
			evidence.Description = fmt.Sprintf("Warning! You may be sharing confidential (%s) data with your code", label)
			if cfile.isTest {
				evidence.Confidence = diagnostics.High
			} else {
				evidence.Confidence = diagnostics.Critical
			}
			return evidence
		}
		if strings.Contains(certType, "public") ||
			certType == "certificate" ||
			certType == "x509 certificate" ||
			certType == "trusted certificate" {
			hasPublicOrCert = true
		}
	}
	if hasPublicOrCert {
		evidence.Description = fmt.Sprintf("Warning! You may be sharing public (%s) data with your code", lastLabel)
		evidence.Confidence = diagnostics.Info
		return evidence
	}
	if lastLabel != "" {
		evidence.Description = fmt.Sprintf("Warning! You may be sharing confidential (%s) data with your code", lastLabel)
	}
	return evidence
}

type confidentialFile struct {
	path   string
	why    string
	isTest bool
}
