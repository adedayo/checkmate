package secrets

import (
	"testing"

	"github.com/adedayo/checkmate/pkg/core/projects"
)

// A repository whose LocationType was never populated used to be dropped by
// the acquisition switch: the scan completed, reported zero findings, and was
// indistinguishable from a clean repository. The desktop app never set the
// field, so every project created through it scanned nothing at all.
func TestResolveLocationType(t *testing.T) {
	cases := []struct {
		name string
		repo projects.Repository
		want string
	}{
		{
			"an explicit type is never second-guessed",
			projects.Repository{Location: "/src/thing", LocationType: "filesystem"},
			"filesystem",
		},
		{
			"an explicit git type survives a path-like location",
			projects.Repository{Location: "/src/thing", LocationType: "git"},
			"git",
		},
		{
			"an unset type on an https URL is git",
			projects.Repository{Location: "https://github.com/adedayo/static-analysis-test-code"},
			"git",
		},
		{
			"an unset type on a git:// URL is git",
			projects.Repository{Location: "git://github.com/adedayo/checkmate.git"},
			"git",
		},
		{
			"an unset type on an ssh:// URL is git",
			projects.Repository{Location: "ssh://git@github.com/adedayo/checkmate.git"},
			"git",
		},
		{
			"an unset type on scp-style shorthand is git",
			projects.Repository{Location: "git@github.com:adedayo/checkmate.git"},
			"git",
		},
		{
			"an unset type on an absolute path is filesystem",
			projects.Repository{Location: "/Users/someone/work/code/thing"},
			"filesystem",
		},
		{
			"an unset type on a relative path is filesystem",
			projects.Repository{Location: "./thing"},
			"filesystem",
		},
		{
			"a Windows drive letter is a path, not scp shorthand",
			projects.Repository{Location: `C:\src\thing`},
			"filesystem",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveLocationType(tc.repo); got != tc.want {
				t.Errorf("resolveLocationType(%+v) = %q, want %q", tc.repo, got, tc.want)
			}
		})
	}
}
