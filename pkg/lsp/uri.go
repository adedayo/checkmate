package lsp

import (
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
)

// PathToFileURI converts a local filesystem path (Unix or Windows) into a
// valid percent-encoded file:// URI. If input is already a file:// URI, it is
// normalised and returned.
func PathToFileURI(p string) string {
	s := strings.TrimSpace(p)
	if s == "" {
		return ""
	}
	if strings.HasPrefix(strings.ToLower(s), "file://") {
		if u, err := url.Parse(s); err == nil {
			return u.String()
		}
		return s
	}

	// Normalise Windows backslashes to forward slashes.
	slashPath := strings.ReplaceAll(s, "\\", "/")
	if isWindowsDrivePath(slashPath) {
		slashPath = "/" + slashPath
	} else if !strings.HasPrefix(slashPath, "/") {
		if abs, err := filepath.Abs(s); err == nil {
			slashPath = filepath.ToSlash(abs)
			if isWindowsDrivePath(slashPath) {
				slashPath = "/" + slashPath
			}
		} else {
			slashPath = "/" + slashPath
		}
	}

	u := url.URL{
		Scheme: "file",
		Path:   slashPath,
	}
	return u.String()
}

// FileURIToPath converts a file:// URI (Unix or Windows, with percent-encoding)
// into a local filesystem path. Non-URI paths are returned cleaned as-is.
func FileURIToPath(rawURI string) (string, error) {
	s := strings.TrimSpace(rawURI)
	if s == "" {
		return "", fmt.Errorf("empty URI")
	}
	if !strings.Contains(s, "://") {
		return filepath.Clean(s), nil
	}

	u, err := url.Parse(s)
	if err != nil {
		return "", fmt.Errorf("parse URI %q: %w", rawURI, err)
	}
	if !strings.EqualFold(u.Scheme, "file") {
		return "", fmt.Errorf("unsupported URI scheme %q", u.Scheme)
	}

	p := u.Path
	if u.Host != "" && !strings.EqualFold(u.Host, "localhost") {
		p = "//" + u.Host + p
	}
	// Strip leading slash before Windows drive letter: /C:/foo -> C:/foo
	if len(p) >= 3 && p[0] == '/' && isASCIIAlpha(p[1]) && p[2] == ':' {
		p = p[1:]
	}
	return filepath.FromSlash(p), nil
}

func isWindowsDrivePath(s string) bool {
	return len(s) >= 2 && isASCIIAlpha(s[0]) && s[1] == ':'
}

func isASCIIAlpha(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}
