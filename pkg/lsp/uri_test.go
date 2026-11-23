package lsp

import (
	"path/filepath"
	"testing"
)

func TestFileURIRoundTrip(t *testing.T) {
	cases := []struct {
		name     string
		path     string
		wantURI  string
		wantPath string
	}{
		{
			name:     "unix simple",
			path:     "/tmp/project/main.go",
			wantURI:  "file:///tmp/project/main.go",
			wantPath: filepath.FromSlash("/tmp/project/main.go"),
		},
		{
			name:     "unix spaces and unicode",
			path:     "/tmp/my project/café file.py",
			wantURI:  "file:///tmp/my%20project/caf%C3%A9%20file.py",
			wantPath: filepath.FromSlash("/tmp/my project/café file.py"),
		},
		{
			name:     "windows drive path",
			path:     `C:\Users\dev\my app\config.yaml`,
			wantURI:  "file:///C:/Users/dev/my%20app/config.yaml",
			wantPath: filepath.FromSlash("C:/Users/dev/my app/config.yaml"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			uri := PathToFileURI(tc.path)
			if uri != tc.wantURI {
				t.Errorf("PathToFileURI(%q) = %q, want %q", tc.path, uri, tc.wantURI)
			}
			gotPath, err := FileURIToPath(uri)
			if err != nil {
				t.Fatalf("FileURIToPath(%q): %v", uri, err)
			}
			if gotPath != tc.wantPath {
				t.Errorf("FileURIToPath(%q) = %q, want %q", uri, gotPath, tc.wantPath)
			}
		})
	}
}
