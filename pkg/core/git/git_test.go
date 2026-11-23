package gitutils

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"golang.org/x/crypto/ssh"
)

func createBareGitRepoWithCommit(t *testing.T, filename, content string) (string, func(filename, content string)) {
	t.Helper()

	bareDir := filepath.Join(t.TempDir(), "remote.git")
	if _, err := git.PlainInit(bareDir, true); err != nil {
		t.Fatalf("init bare repo: %v", err)
	}

	workDir := filepath.Join(t.TempDir(), "work")
	repo, err := git.PlainInit(workDir, false)
	if err != nil {
		t.Fatalf("init work repo: %v", err)
	}

	addAndPush := func(fname, body string) {
		fullPath := filepath.Join(workDir, fname)
		if err := os.WriteFile(fullPath, []byte(body), 0600); err != nil {
			t.Fatalf("write file: %v", err)
		}
		wt, err := repo.Worktree()
		if err != nil {
			t.Fatalf("worktree: %v", err)
		}
		if _, err := wt.Add(fname); err != nil {
			t.Fatalf("git add: %v", err)
		}
		if _, err := wt.Commit("update "+fname, &git.CommitOptions{
			Author: &object.Signature{
				Name:  "Test User",
				Email: "test@example.com",
				When:  time.Now(),
			},
		}); err != nil {
			t.Fatalf("git commit: %v", err)
		}

		// Push via git CLI or go-git remote
		cmd := exec.Command("git", "-C", workDir, "push", bareDir, "HEAD:refs/heads/master")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git push to bare repo failed: %v: %s", err, string(out))
		}
		// Ensure bare HEAD points to master
		_ = os.WriteFile(filepath.Join(bareDir, "HEAD"), []byte("ref: refs/heads/master\n"), 0600)
	}

	addAndPush(filename, content)
	return bareDir, addAndPush
}

// newSmartHTTPGitHandler serves a bare git repo over git smart HTTP protocol
// (git upload-pack --stateless-rpc), optionally enforcing HTTP Basic Auth.
func newSmartHTTPGitHandler(t *testing.T, bareDir, expectedToken string) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if expectedToken != "" {
			_, pass, ok := r.BasicAuth()
			if !ok || pass != expectedToken {
				w.Header().Set("WWW-Authenticate", `Basic realm="git"`)
				http.Error(w, "authentication required", http.StatusUnauthorized)
				return
			}
		}

		if strings.HasSuffix(r.URL.Path, "/info/refs") && r.URL.Query().Get("service") == "git-upload-pack" {
			w.Header().Set("Content-Type", "application/x-git-upload-pack-advertisement")
			cmd := exec.Command("git", "upload-pack", "--stateless-rpc", "--advertise-refs", bareDir)
			out, err := cmd.Output()
			if err != nil {
				http.Error(w, fmt.Sprintf("advertise refs failed: %v", err), http.StatusInternalServerError)
				return
			}
			pkt := "# service=git-upload-pack\n"
			_, _ = fmt.Fprintf(w, "%04x%s0000", len(pkt)+4, pkt)
			_, _ = w.Write(out)
			return
		}

		if strings.HasSuffix(r.URL.Path, "/git-upload-pack") {
			w.Header().Set("Content-Type", "application/x-git-upload-pack-result")
			reqBody, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			cmd := exec.Command("git", "upload-pack", "--stateless-rpc", bareDir)
			cmd.Stdin = bytes.NewReader(reqBody)
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			if err := cmd.Run(); err != nil {
				http.Error(w, fmt.Sprintf("upload-pack failed: %v: %s", err, stderr.String()), http.StatusInternalServerError)
				return
			}
			_, _ = w.Write(stdout.Bytes())
			return
		}

		http.NotFound(w, r)
	})
}

func TestGetCheckoutLocationCollisionFree(t *testing.T) {
	base := t.TempDir()
	locA, err := GetCheckoutLocation("https://github.com/orgA/service.git", base)
	if err != nil {
		t.Fatalf("locA: %v", err)
	}
	locB, err := GetCheckoutLocation("https://github.com/orgB/service.git", base)
	if err != nil {
		t.Fatalf("locB: %v", err)
	}
	if locA == locB {
		t.Fatalf("expected distinct checkout locations for orgA/service and orgB/service, got %s", locA)
	}
	if !strings.HasPrefix(filepath.Base(locA), "service-") {
		t.Fatalf("expected service-<hash>, got %s", filepath.Base(locA))
	}

	// Deterministic with and without .git suffix and with stripped credentials
	locA2, err := GetCheckoutLocation("https://user:tok@github.com/orgA/service", base)
	if err != nil {
		t.Fatalf("locA2: %v", err)
	}
	if locA != locA2 {
		t.Fatalf("expected same checkout dir for same repo with/without .git or credentials: %s vs %s", locA, locA2)
	}

	// SSH URL produces valid distinct name
	locSSH, err := GetCheckoutLocation("git@github.com:orgA/service.git", base)
	if err != nil {
		t.Fatalf("locSSH: %v", err)
	}
	if !strings.HasPrefix(filepath.Base(locSSH), "service-") {
		t.Fatalf("expected service-<hash> for SSH URL, got %s", filepath.Base(locSSH))
	}
}

func TestSanitiseRepoURL(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"https://user:ghp_secret123@github.com/org/repo.git", "https://github.com/org/repo.git"},
		{"https://ghp_secret123@github.com/org/repo.git", "https://github.com/org/repo.git"},
		{"https://github.com/org/repo.git", "https://github.com/org/repo.git"},
		{"git@github.com:org/repo.git", "git@github.com:org/repo.git"},
		{"ssh://git@github.com/org/repo.git", "ssh://git@github.com/org/repo.git"},
		{"ssh://git:secretpass@github.com/org/repo.git", "ssh://git@github.com/org/repo.git"},
		{"/local/path/to/repo", "/local/path/to/repo"},
	}

	for _, tc := range cases {
		got := SanitiseRepoURL(tc.in)
		if got != tc.want {
			t.Errorf("SanitiseRepoURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestIsSSHURLAndExtractors(t *testing.T) {
	if !IsSSHURL("git@github.com:adedayo/checkmate.git") {
		t.Error("expected scp-style git@ URL to be SSH")
	}
	if !IsSSHURL("ssh://git@gitlab.example.com/team/repo.git") {
		t.Error("expected ssh:// URL to be SSH")
	}
	if !IsSSHURL("git+ssh://deploy@host.internal/repo.git") {
		t.Error("expected git+ssh:// URL to be SSH")
	}
	if IsSSHURL("https://github.com/adedayo/checkmate.git") {
		t.Error("expected https URL not to be SSH")
	}
	if IsSSHURL("/tmp/user@host:dir") {
		t.Error("expected absolute local path not to be SSH")
	}
	if ExtractRepoHost("git@github.com:adedayo/checkmate.git") != "github.com" {
		t.Errorf("unexpected host: %s", ExtractRepoHost("git@github.com:adedayo/checkmate.git"))
	}
	if ExtractSSHUser("deploy@host.internal:org/repo.git") != "deploy" {
		t.Errorf("unexpected ssh user: %s", ExtractSSHUser("deploy@host.internal:org/repo.git"))
	}
}

func TestCloneSmartHTTPPublicAuthAndRefresh(t *testing.T) {
	bareDir, addAndPush := createBareGitRepoWithCommit(t, "hello.txt", "version-1")
	const secretToken = "super-secret-token"

	// Auth-protected server
	srv := httptest.NewServer(newSmartHTTPGitHandler(t, bareDir, secretToken))
	defer srv.Close()

	repoURL := srv.URL + "/org/sample.git"
	baseDir := t.TempDir()

	// 1. Fails without credentials and classifies as auth_failed
	_, err := Clone(context.Background(), repoURL, &GitCloneOptions{
		BaseDir: baseDir,
		Depth:   1,
	})
	if err == nil {
		t.Fatalf("expected clone without auth to fail")
	}
	if kind := ClassifyCloneError(err); kind != AcqErrAuth {
		t.Fatalf("expected ClassifyCloneError=%q, got %q (err=%v)", AcqErrAuth, kind, err)
	}

	// Clean failed empty dir before next clone
	baseDir2 := t.TempDir()

	// 2. Explicit missing serviceID returns ErrServiceNotFound (never falls back)
	resolverWithMissing := &ChainedAuthResolver{
		Config: &GitServiceConfig{
			GitServices: map[GitServiceType]map[string]*GitService{},
		},
		ExplicitAuth: &GitAuth{User: "u", Credential: secretToken},
		DisableEnv:   true,
	}
	_, err = Clone(context.Background(), repoURL, &GitCloneOptions{
		BaseDir:      baseDir2,
		Depth:        1,
		ServiceID:    "does-not-exist",
		AuthResolver: resolverWithMissing,
	})
	if !errors.Is(err, ErrServiceNotFound) {
		t.Fatalf("expected ErrServiceNotFound, got %v", err)
	}

	// 3. Host-matched GitServiceConfig succeeds and creates 0700 directory
	baseDir3 := t.TempDir()
	hostResolver := &ChainedAuthResolver{
		Config: &GitServiceConfig{
			GitServices: map[GitServiceType]map[string]*GitService{
				GitHub: {
					"svc-1": {
						ID:          "svc-1",
						InstanceURL: srv.URL,
						API_Key:     secretToken,
						Type:        GitHub,
					},
				},
			},
		},
		DisableEnv: true,
	}
	detail, err := Clone(context.Background(), repoURL, &GitCloneOptions{
		BaseDir:      baseDir3,
		Depth:        1,
		AuthResolver: hostResolver,
	})
	if err != nil {
		t.Fatalf("expected authenticated clone to succeed, got %v", err)
	}

	info, err := os.Stat(detail.Location)
	if err != nil {
		t.Fatalf("stat checkout dir: %v", err)
	}
	if info.Mode().Perm() != 0700 {
		t.Fatalf("expected 0700 permissions on checkout dir, got %o", info.Mode().Perm())
	}

	got, err := os.ReadFile(filepath.Join(detail.Location, "hello.txt"))
	if err != nil {
		t.Fatalf("read hello.txt: %v", err)
	}
	if string(got) != "version-1" {
		t.Fatalf("expected version-1, got %q", string(got))
	}

	// 4. Push a new commit to the bare repo and re-clone into the SAME BaseDir:
	// the working tree MUST be reset to version-2 (not stale version-1).
	addAndPush("hello.txt", "version-2")
	detail2, err := Clone(context.Background(), repoURL, &GitCloneOptions{
		BaseDir:      baseDir3,
		Depth:        0,
		AuthResolver: hostResolver,
	})
	if err != nil {
		t.Fatalf("re-clone refresh failed: %v", err)
	}
	if detail2.Location != detail.Location {
		t.Fatalf("expected same checkout path on refresh")
	}
	got2, err := os.ReadFile(filepath.Join(detail2.Location, "hello.txt"))
	if err != nil {
		t.Fatalf("read hello.txt after refresh: %v", err)
	}
	if string(got2) != "version-2" {
		t.Fatalf("expected refreshed working tree to have version-2, got %q", string(got2))
	}
}

func TestCloneTLSVerificationDefaultFalse(t *testing.T) {
	bareDir, _ := createBareGitRepoWithCommit(t, "readme.txt", "tls-test")
	tlsSrv := httptest.NewTLSServer(newSmartHTTPGitHandler(t, bareDir, ""))
	defer tlsSrv.Close()

	repoURL := tlsSrv.URL + "/org/tlsrepo.git"

	// Default (InsecureSkipTLS: false) must reject self-signed cert
	_, err := Clone(context.Background(), repoURL, &GitCloneOptions{
		BaseDir: t.TempDir(),
		Depth:   1,
	})
	if err == nil {
		t.Fatalf("expected self-signed TLS clone to fail by default")
	}
	if kind := ClassifyCloneError(err); kind != AcqErrTLS {
		t.Fatalf("expected AcqErrTLS, got %q (err=%v)", kind, err)
	}

	// Opt-in InsecureSkipTLS: true succeeds
	detail, err := Clone(context.Background(), repoURL, &GitCloneOptions{
		BaseDir:         t.TempDir(),
		Depth:           1,
		InsecureSkipTLS: true,
	})
	if err != nil {
		t.Fatalf("expected opt-in InsecureSkipTLS clone to succeed, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(detail.Location, "readme.txt")); err != nil {
		t.Fatalf("expected readme.txt in checkout: %v", err)
	}
}

func TestMakeSSHAuthFromKeyFile(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	pemBlock, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("marshal ssh key: %v", err)
	}
	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(pemBlock), 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	resolver := &ChainedAuthResolver{
		ExplicitSSH: &SSHAuthConfig{PrivateKeyPath: keyPath},
		DisableEnv:  true,
	}
	auth, err := resolver.Resolve("git@github.com:adedayo/checkmate.git", "")
	if err != nil {
		t.Fatalf("resolve ssh auth: %v", err)
	}
	if auth == nil {
		t.Fatalf("expected non-nil ssh auth method")
	}
	if auth.Name() != "ssh-public-keys" {
		t.Fatalf("unexpected auth method name: %s", auth.Name())
	}
}

func TestChainedAuthResolverEnvPrecedence(t *testing.T) {
	t.Setenv("CHECKMATE_GIT_TOKEN", "")
	t.Setenv("GITHUB_TOKEN", "gh-tok")
	t.Setenv("GITLAB_TOKEN", "gl-tok")

	r := NewEnvAuthResolver()
	authGH, err := r.Resolve("https://github.com/org/repo.git", "")
	if err != nil || authGH == nil {
		t.Fatalf("expected github env auth, got %v, %v", authGH, err)
	}
	authOther, err := r.Resolve("https://bitbucket.org/org/repo.git", "")
	if err != nil || authOther != nil {
		t.Fatalf("expected nil auth for unrelated host when only GITHUB_TOKEN/GITLAB_TOKEN set, got %v, %v", authOther, err)
	}

	// ClassifyCloneError spot checks
	if ClassifyCloneError(transport.ErrRepositoryNotFound) != AcqErrNotFound {
		t.Fatalf("expected not_found")
	}
	if ClassifyCloneError(transport.ErrAuthenticationRequired) != AcqErrAuth {
		t.Fatalf("expected auth_failed")
	}
}
