package secrets

// Phase 0 harness — reference corpus construction.
//
// The corpus is generated programmatically and materialised into a
// neutrally-named temporary directory rather than being committed under
// `testdata/`. This is deliberate and load-bearing:
//
//	testFile = regexp.MustCompile(`(?i:.*test.*)`)
//
// matches ANY path containing the substring "test". A corpus living under
// `testdata/` — or under a `t.TempDir()` root, which Go names after the
// calling test (e.g. `.../TestScanEquivalence/001`) — would cause every single
// fixture to be classified as a test file and tagged `test`, silently
// invalidating the baseline. `os.MkdirTemp("", "cmcorpus")` avoids the
// substring entirely, so test-file classification is exercised only by
// fixtures that opt into it by name.
//
// All secrets below are FAKE and syntactically valid only. They exist to
// exercise detector branches.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// corpusFile is a single fixture: a path relative to the corpus root and its
// contents.
type corpusFile struct {
	Path    string
	Content string
}

// referenceCorpus returns the full set of fixtures. Ordering is irrelevant —
// findings are canonically sorted — but the slice is kept stable for
// readability of diffs.
//
// Coverage map (every branch of GetFinderForFileType):
//
//	.java/.scala/.kt/.go -> NewJavaFinder
//	.c/.cpp/.cc/...      -> NewCPPSecretsFinders
//	.xml                 -> NewXMLSecretsFinders
//	.yaml/.yml/.json     -> NewYamlSecretsFinders
//	.rb                  -> NewRubySecretsFinders
//	.erb                 -> NewERubySecretsFinders
//	.conf                -> NewConfigurationSecretsFinder
//	"" and everything else -> defaultFinder
func referenceCorpus() []corpusFile {
	return []corpusFile{
		// ---------------------------------------------------------------
		// repo-a — Java-family (NewJavaFinder)
		// ---------------------------------------------------------------
		{
			Path: "repo-a/src/Config.java",
			Content: `package com.example;

public class Config {
    private static final String DB_PASSWORD = "8fJ2!kQz#7vBn4Xw";
    private static final String apiSecret   = "sk_live_4eC39HqLyjWDarjtT1zdp7dc";
    private static final String githubToken = "ghp_016C4Cbb1c0FfFfFfFfFfFfFfFfFfFfFfFf00";
    // not a secret - should not fire
    private static final String NAME = "hello";
}
`,
		},
		{
			Path: "repo-a/src/main.go",
			Content: `package main

const (
	awsSecretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	slackToken   = "xoxb-000000000000-0000000000000-AbCdEfGhIjKlMnOpQrStUvWx"
	publicName   = "checkmate"
)
`,
		},
		{
			Path: "repo-a/src/Settings.kt",
			Content: `object Settings {
    val privateKey: String = "MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX"
    val timeout: Int = 30
}
`,
		},
		{
			Path: "repo-a/src/Creds.scala",
			Content: `object Creds {
  val credential = "R2FsYXh5UXVlc3QxOTk5IQ=="
}
`,
		},

		// ---------------------------------------------------------------
		// repo-a — C/C++ family (NewCPPSecretsFinders, #define branch)
		// ---------------------------------------------------------------
		{
			Path: "repo-a/src/crypto.cpp",
			Content: `#include <string>

#define AUTH_TOKEN L"Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5"
const wchar_t* cipher_key = L"a3f9c2e18b7d4056a3f9c2e18b7d4056";
const char* harmless = "ok";
`,
		},
		{
			Path: "repo-a/include/keys.hpp",
			Content: `#pragma once
static const char* signature_salt = "9d8f7a6b5c4e3d2f1a0b9c8d7e6f5a4b";
`,
		},

		// ---------------------------------------------------------------
		// repo-a — XML (NewXMLSecretsFinders: attribute, tag, long-value)
		// ---------------------------------------------------------------
		{
			Path: "repo-a/conf/app.xml",
			Content: `<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <datasource username="svc_app" password="P%40ssw0rd!2024x"/>
  <credentials>
    <secret>c2VjcmV0LXZhbHVlLTEyMzQ1Njc4OTA=</secret>
    <name>public</name>
  </credentials>
  <token>glpat-AbCdEfGhIjKlMnOpQrSt</token>
</configuration>
`,
		},

		// ---------------------------------------------------------------
		// repo-a — YAML / JSON (NewYamlSecretsFinders)
		// ---------------------------------------------------------------
		{
			Path: "repo-a/conf/settings.yaml",
			Content: `service:
  name: billing
  api_key: "pypi-AgEIcHlwaS5vcmcAAAAAAAAAAAAAAAAA"
  db_password: 'Tr0ub4dor&3xKcd'
  replicas: 3
`,
		},
		{
			Path: "repo-a/conf/package.json",
			Content: `{
  "name": "billing",
  "version": "1.0.0",
  "clientSecret": "8Q~aBcDeFgHiJkLmNoPqRsTuVwXyZ01234567",
  "port": 8080
}
`,
		},

		// ---------------------------------------------------------------
		// repo-a — .conf (NewConfigurationSecretsFinder — no '=' required)
		// ---------------------------------------------------------------
		{
			Path: "repo-a/conf/database.conf",
			Content: `# database configuration
host localhost
port 5432
password "hunter2hunter2hunter2"
connection postgres://svcuser:s3cr3tP4ss@db.internal:5432/billing
`,
		},

		// ---------------------------------------------------------------
		// repo-a — Ruby / ERB
		// ---------------------------------------------------------------
		{
			Path: "repo-a/src/deploy.rb",
			Content: `SECRETS = {
  :auth_token => "f4c3b2a1908e7d6c5b4a39281706f5e4",
  :region     => "eu-west-2"
}
`,
		},
		{
			Path: "repo-a/views/index.erb",
			Content: `<div>
  <% api_secret = "9c8b7a6f5e4d3c2b1a09f8e7d6c5b4a3" %>
  <span><%= user.name %></span>
</div>
`,
		},

		// ---------------------------------------------------------------
		// repo-a — extensionless text file (defaultFinder + text sniff)
		// ---------------------------------------------------------------
		{
			Path: "repo-a/scripts/deploy",
			Content: `#!/bin/sh
export DEPLOY_TOKEN="ghs_1234567890abcdefghijklmnopqrstuvwxyzAB"
echo "deploying"
`,
		},

		// ---------------------------------------------------------------
		// repo-a — unknown extension (must be SKIPPED by extension gate)
		// ---------------------------------------------------------------
		{
			Path: "repo-a/assets/notes.xyz",
			Content: `password = "ThisShouldNeverBeReported12345"
`,
		},

		// ---------------------------------------------------------------
		// repo-a — deliberate test-file paths (exercise the `test` tag and
		// the ExcludeTestFiles option). These are the ONLY fixtures whose
		// paths contain "test".
		// ---------------------------------------------------------------
		{
			Path: "repo-a/tests/AuthTest.java",
			Content: `public class AuthTest {
    static final String password = "TestFixturePassw0rd!x";
}
`,
		},

		// ---------------------------------------------------------------
		// repo-a — confidential files (confidentialFilesFinder branch)
		// ---------------------------------------------------------------
		{
			Path: "repo-a/.env",
			Content: `DATABASE_URL=mysql://root:r00tp4ssw0rd@127.0.0.1:3306/app
STRIPE_KEY=sk_test_4eC39HqLyjWDarjtT1zdp7dc
`,
		},
		{
			Path: "repo-a/certs/server.pem",
			Content: `-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu
KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQJAIJLixBy2qpFoS4DSmoEm
-----END RSA PRIVATE KEY-----
`,
		},

		// ---------------------------------------------------------------
		// repo-b — second root, for multi-repository RepositoryIndex
		// coverage. This is the fixture that exposes the stale
		// `vendorFinders` cache defect (Phase 1): vendor-rule findings here
		// are currently attributed to repo-a's RepositoryIndex.
		// ---------------------------------------------------------------
		{
			Path: "repo-b/src/Client.java",
			Content: `public class Client {
    static final String token = "ghp_ffFFffFFffFFffFFffFFffFFffFFffFF0099";
    static final String gitlab = "glpat-ZyXwVuTsRqPoNmLkJiHg";
}
`,
		},
		{
			Path: "repo-b/conf/values.yaml",
			Content: `credentials:
  secret: "bXktdmVyeS1zZWNyZXQtdmFsdWUtaGVyZQ=="
  enabled: true
`,
		},
	}
}

// adversarialCorpus returns fixtures that target the specific pathologies
// identified in the proposal. These are generated rather than committed
// because several are megabytes in size.
//
// P4 (quadratic readChunks + goroutine storm) is exercised by the files with
// no newlines; P2 (walker) by the symlink loop and deep nesting; the
// unrecognised-extension oversize file exercises the existing 10MB cutOffSize
// skip, which must continue to behave identically.
func adversarialCorpus() []corpusFile {
	var files []corpusFile

	// 10MB minified JavaScript: a single line, no newline anywhere. This is
	// the primary trigger for the O(n^2) `largeChunk +=` branch in readChunks.
	var minified strings.Builder
	minified.WriteString(`!function(e,t){"use strict";var apiKey="ghp_minifiedMINIFIEDminifiedMINIFIED01";`)
	for minified.Len() < 10*1024*1024 {
		minified.WriteString(`function a${N}(x){return x*2;}var b${N}={k:"v",n:1234567890};`)
	}
	files = append(files, corpusFile{Path: "adversarial/bundle.min.js", Content: minified.String()})

	// 4MB single-line JSON — same pathology, different detector branch
	// (NewYamlSecretsFinders rather than defaultFinder).
	var oneLineJSON strings.Builder
	oneLineJSON.WriteString(`{"secret":"c2luZ2xlLWxpbmUtanNvbi1zZWNyZXQtdmFsdWU=","data":[`)
	for oneLineJSON.Len() < 4*1024*1024 {
		oneLineJSON.WriteString(`{"id":1,"name":"item","value":"0123456789abcdef"},`)
	}
	oneLineJSON.WriteString(`{"id":0,"name":"last","value":"f"}]}`)
	files = append(files, corpusFile{Path: "adversarial/oneline.json", Content: oneLineJSON.String()})

	// 2MB unbroken base64 blob — no newlines, no whitespace at all.
	var blob strings.Builder
	blob.WriteString("data = \"")
	const b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	for blob.Len() < 2*1024*1024 {
		blob.WriteString(b64)
	}
	blob.WriteString("==\"\n")
	files = append(files, corpusFile{Path: "adversarial/blob.yaml", Content: blob.String()})

	// Binary content behind a text extension — exercises the binary sniff
	// gap (S7): today only extensionless files are sniffed, so this file is
	// currently scanned in full.
	var bin strings.Builder
	for i := 0; i < 64*1024; i++ {
		bin.WriteByte(byte(i % 256))
	}
	files = append(files, corpusFile{Path: "adversarial/payload.conf", Content: bin.String()})

	// Extensionless binary — currently rejected by the 512-byte
	// DetectContentType sniff. Must stay rejected.
	files = append(files, corpusFile{Path: "adversarial/blobdata", Content: bin.String()})

	// >10MB with an unrecognised-but-textual extension: exercises the
	// cutOffSize skip path in pathBasedSourceSecretFinder.
	var oversize strings.Builder
	oversize.WriteString("password = \"oversizeSecretShouldBeSkipped123\"\n")
	for oversize.Len() < int(TenMB)+1024 {
		oversize.WriteString("filler line with no secrets whatsoever here\n")
	}
	files = append(files, corpusFile{Path: "adversarial/huge.log", Content: oversize.String()})

	// Deeply nested tree — exercises walker recursion depth.
	//
	// Depth is capped so the resulting absolute path stays inside the
	// platform's limit (1024 bytes on macOS, PATH_MAX). 200 levels overflowed
	// it and the fixture failed to build at all, which is a fixture bug rather
	// than an engine finding; 80 levels is still far deeper than any real
	// repository and exercises the same recursion.
	deep := "adversarial/deep"
	for i := 0; i < 80; i++ {
		deep = filepath.Join(deep, fmt.Sprintf("l%03d", i))
	}
	files = append(files, corpusFile{
		Path:    filepath.Join(deep, "buried.yaml"),
		Content: "api_secret: \"deeplyNestedSecretValue123456\"\n",
	})

	return files
}

// scaleCorpus generates `n` small source files, used by throughput benchmarks
// to model a large codebase without committing one. Roughly 1 in 20 files
// contains a finding, approximating a realistic hit rate.
func scaleCorpus(n int) []corpusFile {
	files := make([]corpusFile, 0, n)
	for i := 0; i < n; i++ {
		var content string
		if i%20 == 0 {
			content = fmt.Sprintf(`package pkg%d

const secretValue = "s3cr3t%08dABCDEFGH"

func F%d() int { return %d }
`, i, i, i, i)
		} else {
			content = fmt.Sprintf(`package pkg%d

// ordinary source file with no credentials
func F%d(a, b int) int {
	return a*%d + b
}
`, i, i, i)
		}
		files = append(files, corpusFile{
			Path:    filepath.Join("scale", fmt.Sprintf("d%03d", i%256), fmt.Sprintf("f%06d.go", i)),
			Content: content,
		})
	}
	return files
}

// materialiseCorpus writes `files` into a fresh temporary directory and
// returns its root. The root name deliberately avoids the substring "test"
// (see the package comment above). Cleanup is registered on `tb`.
func materialiseCorpus(tb testing.TB, files []corpusFile) string {
	tb.Helper()

	root, err := os.MkdirTemp("", "cmcorpus")
	if err != nil {
		tb.Fatalf("creating corpus root: %v", err)
	}
	tb.Cleanup(func() { _ = os.RemoveAll(root) })

	if strings.Contains(strings.ToLower(root), "test") {
		tb.Fatalf("corpus root %q contains \"test\"; every fixture would be "+
			"misclassified as a test file and the baseline would be invalid", root)
	}

	for _, f := range files {
		full := filepath.Join(root, filepath.FromSlash(f.Path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			tb.Fatalf("creating %s: %v", filepath.Dir(full), err)
		}
		if err := os.WriteFile(full, []byte(f.Content), 0o644); err != nil {
			tb.Fatalf("writing %s: %v", full, err)
		}
	}
	return root
}

// addSymlinkLoop creates a directory containing a symlink back to an ancestor.
// A walker without a visited-directory guard will recurse indefinitely (or
// until the OS path limit). Returns false when the platform disallows symlink
// creation, so callers can skip.
func addSymlinkLoop(tb testing.TB, root string) bool {
	tb.Helper()

	loopDir := filepath.Join(root, "adversarial", "loop")
	if err := os.MkdirAll(loopDir, 0o755); err != nil {
		tb.Fatalf("creating loop dir: %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(loopDir, "creds.yaml"),
		[]byte("token: \"loopedSecretValue0123456789\"\n"), 0o644,
	); err != nil {
		tb.Fatalf("writing loop fixture: %v", err)
	}
	if err := os.Symlink(root, filepath.Join(loopDir, "back")); err != nil {
		tb.Logf("skipping symlink loop fixture: %v", err)
		return false
	}
	return true
}
