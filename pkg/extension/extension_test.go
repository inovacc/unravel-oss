/* Copyright (c) 2026 Security Research */
package extension

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/manifest"
)

func TestAnalyzePermissions(t *testing.T) {
	rules := []manifest.ExtPermissionRule{
		{Permission: "tabs", Risk: "HIGH"},
		{Permission: "storage", Risk: "LOW"},
		{Permission: "debugger", Risk: "CRITICAL"},
	}

	tests := []struct {
		name        string
		permissions []string
		wantRisk    map[string][]string
	}{
		{
			name:        "classifies known permissions",
			permissions: []string{"tabs", "storage", "debugger"},
			wantRisk: map[string][]string{
				"CRITICAL": {"debugger"},
				"HIGH":     {"tabs"},
				"LOW":      {"storage"},
			},
		},
		{
			name:        "unknown permission goes to UNKNOWN",
			permissions: []string{"someNewPerm"},
			wantRisk: map[string][]string{
				"UNKNOWN": {"someNewPerm"},
			},
		},
		{
			name:        "host pattern all_urls is HIGH",
			permissions: []string{"<all_urls>"},
			wantRisk: map[string][]string{
				"HIGH": {"<all_urls>"},
			},
		},
		{
			name:        "specific host pattern is MEDIUM",
			permissions: []string{"https://example.com/*"},
			wantRisk: map[string][]string{
				"MEDIUM": {"https://example.com/*"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := &ExtensionInfo{
				Permissions: PermissionAnalysis{
					All: tt.permissions,
				},
			}

			AnalyzePermissions(info, rules)

			if info.Permissions.ByRisk == nil {
				t.Fatal("ByRisk should not be nil after AnalyzePermissions")
			}

			for risk, wantPerms := range tt.wantRisk {
				gotPerms := info.Permissions.ByRisk[risk]
				if len(gotPerms) != len(wantPerms) {
					t.Errorf("ByRisk[%q] = %v, want %v", risk, gotPerms, wantPerms)
					continue
				}
				for i, p := range wantPerms {
					if gotPerms[i] != p {
						t.Errorf("ByRisk[%q][%d] = %q, want %q", risk, i, gotPerms[i], p)
					}
				}
			}
		})
	}
}

func TestCalculateRiskScore(t *testing.T) {
	weights := map[string]int{
		"CRITICAL": 50,
		"HIGH":     20,
		"MEDIUM":   10,
		"LOW":      2,
		"UNKNOWN":  5,
	}

	tests := []struct {
		name      string
		info      *ExtensionInfo
		wantLevel string
		wantMin   int
	}{
		{
			name: "CRITICAL when score >= 100",
			info: &ExtensionInfo{
				Permissions: PermissionAnalysis{Critical: 2, High: 1},
			},
			wantLevel: "CRITICAL",
			wantMin:   100,
		},
		{
			name: "HIGH when score >= 50",
			info: &ExtensionInfo{
				Permissions: PermissionAnalysis{Critical: 1},
			},
			wantLevel: "HIGH",
			wantMin:   50,
		},
		{
			name: "MEDIUM when score >= 20",
			info: &ExtensionInfo{
				Permissions: PermissionAnalysis{High: 1},
			},
			wantLevel: "MEDIUM",
			wantMin:   20,
		},
		{
			name: "LOW when score < 20",
			info: &ExtensionInfo{
				Permissions: PermissionAnalysis{Low: 1},
			},
			wantLevel: "LOW",
			wantMin:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			CalculateRiskScore(tt.info, weights)

			if tt.info.RiskLevel != tt.wantLevel {
				t.Errorf("RiskLevel = %q, want %q (score=%d)", tt.info.RiskLevel, tt.wantLevel, tt.info.RiskScore)
			}
			if tt.info.RiskScore < tt.wantMin {
				t.Errorf("RiskScore = %d, want >= %d", tt.info.RiskScore, tt.wantMin)
			}
		})
	}
}

func TestIsExtensionPackage(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"extension.crx", true},
		{"extension.CRX", true},
		{"archive.zip", true},
		{"addon.xpi", true},
		{"readme.txt", false},
		{"", false},
		{"noext", false},
		{"file.crx.bak", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := isExtensionPackage(tt.path); got != tt.want {
				t.Errorf("isExtensionPackage(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestIsHostPattern(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"*://example.com/*", true},
		{"https://example.com/*", true},
		{"http://localhost/*", true},
		{"<all_urls>", true},
		{"ftp://files.example.com/*", true},
		{"tabs", false},
		{"storage", false},
		{"debugger", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := isHostPattern(tt.input); got != tt.want {
				t.Errorf("isHostPattern(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestBeautifyJS(t *testing.T) {
	tests := []struct {
		name string
		code string
		want []string // substrings that must appear in output
	}{
		{
			name: "adds newline after open brace",
			code: "function f(){return 1;}",
			want: []string{"{\n", "return 1;"},
		},
		{
			name: "adds newline before close brace",
			code: "if(x){y=1;}",
			want: []string{"\n}"},
		},
		{
			name: "adds newline after semicolon",
			code: "a=1;b=2;c=3;",
			want: []string{"a=1;\n", "b=2;\n"},
		},
		{
			name: "preserves strings with braces",
			code: `var s="hello{world}";`,
			want: []string{`"hello{world}"`},
		},
		{
			name: "empty input returns empty",
			code: "",
			want: []string{""},
		},
		{
			name: "semicolons inside for loop stay on same line",
			code: "for(var i=0;i<10;i++){x++;}",
			want: []string{"for(var i=0;i<10;i++)"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := beautifyJS(tt.code)
			for _, sub := range tt.want {
				if !strings.Contains(got, sub) {
					t.Errorf("beautifyJS(%q) missing substring %q\ngot: %q", tt.code, sub, got)
				}
			}
		})
	}
}

func TestBIsInsideForLoop(t *testing.T) {
	tests := []struct {
		name string
		code string
		pos  int
		want bool
	}{
		{
			name: "semicolon inside for parens",
			code: "for(var i=0;i<10;i++){x++;}",
			pos:  11,
			want: true,
		},
		{
			name: "semicolon after for body",
			code: "for(var i=0;i<10;i++){x++;}",
			pos:  26,
			want: false,
		},
		{
			name: "no for keyword",
			code: "var x=1;var y=2;",
			pos:  7,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := bIsInsideForLoop(tt.code, tt.pos); got != tt.want {
				t.Errorf("bIsInsideForLoop(%q, %d) = %v, want %v", tt.code, tt.pos, got, tt.want)
			}
		})
	}
}

func TestReadCRXPayload(t *testing.T) {
	t.Run("valid CRX v2", func(t *testing.T) {
		zipData := buildMinimalZIP(t)

		var buf bytes.Buffer
		buf.WriteString("Cr24")
		_ = binary.Write(&buf, binary.LittleEndian, uint32(2))
		_ = binary.Write(&buf, binary.LittleEndian, uint32(4))
		_ = binary.Write(&buf, binary.LittleEndian, uint32(4))
		buf.Write([]byte("PUBK"))
		buf.Write([]byte("SIGN"))
		buf.Write(zipData)

		path := filepath.Join(t.TempDir(), "test.crx")
		if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}

		payload, err := readCRXPayload(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !bytes.Equal(payload, zipData) {
			t.Errorf("payload mismatch: got %d bytes, want %d bytes", len(payload), len(zipData))
		}
	})

	t.Run("valid CRX v3", func(t *testing.T) {
		zipData := buildMinimalZIP(t)

		var buf bytes.Buffer
		buf.WriteString("Cr24")
		_ = binary.Write(&buf, binary.LittleEndian, uint32(3))
		_ = binary.Write(&buf, binary.LittleEndian, uint32(8))
		buf.Write([]byte("HEADDATA"))
		buf.Write(zipData)

		path := filepath.Join(t.TempDir(), "test.crx")
		if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}

		payload, err := readCRXPayload(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !bytes.Equal(payload, zipData) {
			t.Errorf("payload mismatch")
		}
	})

	t.Run("invalid magic", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "bad.crx")
		if err := os.WriteFile(path, []byte("NOT_CRX_XXXXXXXX"), 0o644); err != nil {
			t.Fatal(err)
		}

		_, err := readCRXPayload(path)
		if err == nil {
			t.Fatal("expected error for invalid magic")
		}
	})

	t.Run("file too small", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "tiny.crx")
		if err := os.WriteFile(path, []byte("Cr24"), 0o644); err != nil {
			t.Fatal(err)
		}

		_, err := readCRXPayload(path)
		if err == nil {
			t.Fatal("expected error for too-small file")
		}
	})

	t.Run("unsupported version", func(t *testing.T) {
		var buf bytes.Buffer
		buf.WriteString("Cr24")
		_ = binary.Write(&buf, binary.LittleEndian, uint32(99))
		_ = binary.Write(&buf, binary.LittleEndian, uint32(0))

		path := filepath.Join(t.TempDir(), "v99.crx")
		if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}

		_, err := readCRXPayload(path)
		if err == nil {
			t.Fatal("expected error for unsupported version")
		}
	})
}

func TestExtractZIPBytes(t *testing.T) {
	t.Run("extracts files from zip", func(t *testing.T) {
		zipData := buildZIPWithFiles(t, map[string]string{
			"manifest.json": `{"name":"test"}`,
			"bg.js":         "console.log('hi');",
		})

		destDir := t.TempDir()
		if err := extractZIPBytes(zipData, destDir); err != nil {
			t.Fatalf("extractZIPBytes: %v", err)
		}

		content, err := os.ReadFile(filepath.Join(destDir, "manifest.json"))
		if err != nil {
			t.Fatalf("read manifest.json: %v", err)
		}

		if string(content) != `{"name":"test"}` {
			t.Errorf("manifest.json content = %q, want %q", string(content), `{"name":"test"}`)
		}

		content, err = os.ReadFile(filepath.Join(destDir, "bg.js"))
		if err != nil {
			t.Fatalf("read bg.js: %v", err)
		}

		if string(content) != "console.log('hi');" {
			t.Errorf("bg.js content mismatch")
		}
	})

	t.Run("invalid zip data", func(t *testing.T) {
		err := extractZIPBytes([]byte("not a zip"), t.TempDir())
		if err == nil {
			t.Fatal("expected error for invalid zip data")
		}
	})
}

func TestParseExtension(t *testing.T) {
	t.Run("parses manifest from directory", func(t *testing.T) {
		dir := t.TempDir()
		m := ChromeManifest{
			ManifestVersion: 3,
			Name:            "Test Extension",
			Version:         "1.2.3",
			Description:     "A test extension",
			Permissions:     []any{"tabs", "storage"},
			HostPermissions: []string{"https://example.com/*"},
		}

		data, _ := json.Marshal(m)
		if err := os.WriteFile(filepath.Join(dir, "manifest.json"), data, 0o644); err != nil {
			t.Fatal(err)
		}

		info, err := ParseExtension(dir, "test-id", "chrome", "Default")
		if err != nil {
			t.Fatalf("ParseExtension: %v", err)
		}

		if info.Name != "Test Extension" {
			t.Errorf("Name = %q, want %q", info.Name, "Test Extension")
		}

		if info.Version != "1.2.3" {
			t.Errorf("Version = %q, want %q", info.Version, "1.2.3")
		}

		if info.ManifestVer != 3 {
			t.Errorf("ManifestVer = %d, want 3", info.ManifestVer)
		}

		if info.ID != "test-id" {
			t.Errorf("ID = %q, want %q", info.ID, "test-id")
		}

		if info.Browser != "chrome" {
			t.Errorf("Browser = %q, want %q", info.Browser, "chrome")
		}

		if len(info.Permissions.All) != 3 {
			t.Errorf("Permissions.All length = %d, want 3: %v", len(info.Permissions.All), info.Permissions.All)
		}
	})

	t.Run("parses manifest from version subdirectory", func(t *testing.T) {
		dir := t.TempDir()
		versionDir := filepath.Join(dir, "1.0.0")
		if err := os.MkdirAll(versionDir, 0o755); err != nil {
			t.Fatal(err)
		}

		m := ChromeManifest{
			ManifestVersion: 2,
			Name:            "Sub Extension",
			Version:         "1.0.0",
		}

		data, _ := json.Marshal(m)
		if err := os.WriteFile(filepath.Join(versionDir, "manifest.json"), data, 0o644); err != nil {
			t.Fatal(err)
		}

		info, err := ParseExtension(dir, "sub-id", "edge", "Profile 1")
		if err != nil {
			t.Fatalf("ParseExtension: %v", err)
		}

		if info.Name != "Sub Extension" {
			t.Errorf("Name = %q, want %q", info.Name, "Sub Extension")
		}
	})

	t.Run("error on missing manifest", func(t *testing.T) {
		dir := t.TempDir()
		_, err := ParseExtension(dir, "missing", "chrome", "Default")
		if err == nil {
			t.Fatal("expected error for missing manifest.json")
		}
	})

	t.Run("error on invalid JSON", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte("{invalid}"), 0o644); err != nil {
			t.Fatal(err)
		}

		_, err := ParseExtension(dir, "bad-json", "chrome", "Default")
		if err == nil {
			t.Fatal("expected error for invalid JSON")
		}
	})
}

func TestSanitizeName(t *testing.T) {
	tests := []struct {
		name    string
		browser string
		want    string
	}{
		{"Simple Extension", "chrome", "Simple_Extension_(chrome)"},
		{"Test<>:\"/\\|?*&Name", "edge", "Test_Name_(edge)"},
		{"   spaces   ", "chrome", "spaces_(chrome)"},
		{"___underscores___", "brave", "underscores_(brave)"},
		{"", "chrome", "unknown_(chrome)"},
		{"a/b\\c:d", "chrome", "a_b_c_d_(chrome)"},
	}

	for _, tt := range tests {
		t.Run(tt.name+"_"+tt.browser, func(t *testing.T) {
			got := sanitizeName(tt.name, tt.browser)
			if got != tt.want {
				t.Errorf("sanitizeName(%q, %q) = %q, want %q", tt.name, tt.browser, got, tt.want)
			}
		})
	}
}

func TestNormalizePermissions(t *testing.T) {
	tests := []struct {
		name string
		cm   ChromeManifest
		want []string
	}{
		{
			name: "V2 permissions without hosts",
			cm: ChromeManifest{
				Permissions: []any{"tabs", "storage"},
			},
			want: []string{"tabs", "storage"},
		},
		{
			name: "V2 host patterns excluded from permissions",
			cm: ChromeManifest{
				Permissions: []any{"tabs", "https://example.com/*"},
			},
			want: []string{"tabs"},
		},
		{
			name: "V3 host_permissions included",
			cm: ChromeManifest{
				Permissions:     []any{"tabs"},
				HostPermissions: []string{"https://example.com/*"},
			},
			want: []string{"tabs", "https://example.com/*"},
		},
		{
			name: "deduplicates",
			cm: ChromeManifest{
				Permissions:    []any{"tabs"},
				OptPermissions: []any{"tabs", "storage"},
			},
			want: []string{"tabs", "storage"},
		},
		{
			name: "empty manifest",
			cm:   ChromeManifest{},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizePermissions(tt.cm)
			if len(got) != len(tt.want) {
				t.Errorf("normalizePermissions() = %v, want %v", got, tt.want)
				return
			}

			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("normalizePermissions()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestExtractHosts(t *testing.T) {
	tests := []struct {
		name string
		cm   ChromeManifest
		want []string
	}{
		{
			name: "V2 host patterns from permissions",
			cm: ChromeManifest{
				Permissions: []any{"tabs", "https://example.com/*"},
			},
			want: []string{"https://example.com/*"},
		},
		{
			name: "V3 host_permissions",
			cm: ChromeManifest{
				HostPermissions: []string{"https://api.example.com/*"},
			},
			want: []string{"https://api.example.com/*"},
		},
		{
			name: "deduplicates across V2 and V3",
			cm: ChromeManifest{
				Permissions:     []any{"https://example.com/*"},
				HostPermissions: []string{"https://example.com/*"},
			},
			want: []string{"https://example.com/*"},
		},
		{
			name: "no hosts",
			cm: ChromeManifest{
				Permissions: []any{"tabs", "storage"},
			},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractHosts(tt.cm)
			if len(got) != len(tt.want) {
				t.Errorf("extractHosts() = %v, want %v", got, tt.want)
				return
			}

			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("extractHosts()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestCalculateRiskScoreWithFindings(t *testing.T) {
	weights := map[string]int{
		"CRITICAL": 50,
		"HIGH":     20,
		"MEDIUM":   10,
		"LOW":      2,
		"UNKNOWN":  5,
	}

	t.Run("code findings add to score", func(t *testing.T) {
		info := &ExtensionInfo{
			CodeFindings: []CodeFinding{
				{Risk: "HIGH"},
				{Risk: "MEDIUM"},
			},
		}

		CalculateRiskScore(info, weights)

		if info.RiskScore != 30 {
			t.Errorf("RiskScore = %d, want 30", info.RiskScore)
		}
	})

	t.Run("stealth findings add to score", func(t *testing.T) {
		info := &ExtensionInfo{
			StealthFlags: []StealthFinding{
				{Risk: "CRITICAL"},
			},
		}

		CalculateRiskScore(info, weights)

		if info.RiskScore != 50 {
			t.Errorf("RiskScore = %d, want 50", info.RiskScore)
		}
	})

	t.Run("cheating flags use HIGH weight", func(t *testing.T) {
		info := &ExtensionInfo{
			CheatingFlags: []string{"cheat1", "cheat2"},
		}

		CalculateRiskScore(info, weights)

		if info.RiskScore != 40 {
			t.Errorf("RiskScore = %d, want 40", info.RiskScore)
		}
	})
}

func TestFindLatestVersion(t *testing.T) {
	t.Run("manifest in root", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}

		got, err := findLatestVersion(dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got != dir {
			t.Errorf("findLatestVersion() = %q, want %q", got, dir)
		}
	})

	t.Run("manifest in version subdir", func(t *testing.T) {
		dir := t.TempDir()
		vDir := filepath.Join(dir, "2.0.0")
		if err := os.MkdirAll(vDir, 0o755); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(filepath.Join(vDir, "manifest.json"), []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}

		got, err := findLatestVersion(dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got != vDir {
			t.Errorf("findLatestVersion() = %q, want %q", got, vDir)
		}
	})

	t.Run("skips _metadata and Temp dirs", func(t *testing.T) {
		dir := t.TempDir()

		for _, skip := range []string{"_metadata", "Temp"} {
			if err := os.MkdirAll(filepath.Join(dir, skip), 0o755); err != nil {
				t.Fatal(err)
			}
		}

		realDir := filepath.Join(dir, "1.0.0")
		if err := os.MkdirAll(realDir, 0o755); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(filepath.Join(realDir, "manifest.json"), []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}

		got, err := findLatestVersion(dir)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got != realDir {
			t.Errorf("findLatestVersion() = %q, want %q", got, realDir)
		}
	})

	t.Run("empty dir errors", func(t *testing.T) {
		dir := t.TempDir()
		_, err := findLatestVersion(dir)
		if err == nil {
			t.Fatal("expected error for empty dir")
		}
	})
}

func TestEnrichExtensionData(t *testing.T) {
	dir := t.TempDir()

	// Create some test files
	if err := os.WriteFile(filepath.Join(dir, "background.js"), []byte("console.log('bg');"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(dir, "style.css"), []byte("body{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(dir, "popup.html"), []byte("<html></html>"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(dir, "data.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	info := &ExtensionInfo{Path: dir}
	enrichExtensionData(info)

	if info.FileStats.TotalFiles != 4 {
		t.Errorf("TotalFiles = %d, want 4", info.FileStats.TotalFiles)
	}

	if info.FileStats.JavaScriptFiles != 1 {
		t.Errorf("JavaScriptFiles = %d, want 1", info.FileStats.JavaScriptFiles)
	}

	if info.FileStats.CSSFiles != 1 {
		t.Errorf("CSSFiles = %d, want 1", info.FileStats.CSSFiles)
	}

	if info.FileStats.HTMLFiles != 1 {
		t.Errorf("HTMLFiles = %d, want 1", info.FileStats.HTMLFiles)
	}

	if info.FileStats.JSONFiles != 1 {
		t.Errorf("JSONFiles = %d, want 1", info.FileStats.JSONFiles)
	}

	if len(info.ScriptFiles) != 1 || info.ScriptFiles[0] != "background.js" {
		t.Errorf("ScriptFiles = %v, want [background.js]", info.ScriptFiles)
	}
}

func TestEnrichExtensionDataEndpoints(t *testing.T) {
	dir := t.TempDir()

	jsContent := `
		var ws = new WebSocket("wss://example.com/socket");
		fetch("https://api.example.com/data");
		chrome.runtime.connectNative("com.example.host");
	`
	if err := os.WriteFile(filepath.Join(dir, "app.js"), []byte(jsContent), 0o644); err != nil {
		t.Fatal(err)
	}

	info := &ExtensionInfo{Path: dir}
	enrichExtensionData(info)

	if len(info.WebSocketEndpoints) == 0 {
		t.Error("expected WebSocketEndpoints to be populated")
	}

	if len(info.URLEndpoints) == 0 {
		t.Error("expected URLEndpoints to be populated")
	}

	if len(info.NativeMessagingHosts) == 0 {
		t.Error("expected NativeMessagingHosts to be populated")
	}
}

func TestExtractExtensionPackage(t *testing.T) {
	t.Run("extracts zip file", func(t *testing.T) {
		zipData := buildZIPWithFiles(t, map[string]string{
			"manifest.json": `{"name":"test"}`,
		})

		zipPath := filepath.Join(t.TempDir(), "ext.zip")
		if err := os.WriteFile(zipPath, zipData, 0o644); err != nil {
			t.Fatal(err)
		}

		destDir := t.TempDir()
		if err := extractExtensionPackage(zipPath, destDir); err != nil {
			t.Fatalf("extractExtensionPackage: %v", err)
		}

		if _, err := os.Stat(filepath.Join(destDir, "manifest.json")); err != nil {
			t.Errorf("manifest.json not extracted: %v", err)
		}
	})

	t.Run("extracts xpi file", func(t *testing.T) {
		zipData := buildZIPWithFiles(t, map[string]string{
			"manifest.json": `{"name":"firefox"}`,
		})

		xpiPath := filepath.Join(t.TempDir(), "addon.xpi")
		if err := os.WriteFile(xpiPath, zipData, 0o644); err != nil {
			t.Fatal(err)
		}

		destDir := t.TempDir()
		if err := extractExtensionPackage(xpiPath, destDir); err != nil {
			t.Fatalf("extractExtensionPackage: %v", err)
		}
	})

	t.Run("unsupported format", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "ext.tar")
		if err := os.WriteFile(path, []byte("data"), 0o644); err != nil {
			t.Fatal(err)
		}

		err := extractExtensionPackage(path, t.TempDir())
		if err == nil {
			t.Fatal("expected error for unsupported format")
		}
	})
}

func TestCountExtensions(t *testing.T) {
	dir := t.TempDir()

	// Create extension dirs
	for _, name := range []string{"ext1", "ext2", "Temp"} {
		if err := os.MkdirAll(filepath.Join(dir, name), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	// Create a file (should be ignored)
	if err := os.WriteFile(filepath.Join(dir, "file.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	got := countExtensions(dir)
	if got != 2 {
		t.Errorf("countExtensions() = %d, want 2", got)
	}
}

func TestNewCompiledScanner(t *testing.T) {
	m := &manifest.Manifest{
		Extension: manifest.ExtensionConfig{
			DangerousPermissions: []manifest.ExtPermissionRule{
				{Permission: "tabs", Risk: "HIGH"},
			},
			SuspiciousPatterns: []manifest.SuspiciousPattern{
				{Name: "eval", Description: "Dynamic code", Patterns: []string{`eval\(`}, Risk: "HIGH"},
				{Name: "badpat", Description: "Invalid regex", Patterns: []string{`[`}, Risk: "LOW"},
			},
			StealthPatterns: []manifest.StealthPattern{
				{Name: "stealth1", Description: "Screen hide", Patterns: []string{`contentProtection`}, Risk: "CRITICAL"},
			},
			CheatingKeywords: []string{"interview", "assistant"},
		},
		RiskScoring: manifest.RiskConfig{
			Weights: map[string]int{"HIGH": 20, "CRITICAL": 50, "LOW": 2},
		},
	}

	cs := newCompiledScanner(m)

	if len(cs.suspicious) != 2 {
		t.Errorf("suspicious count = %d, want 2", len(cs.suspicious))
	}

	if len(cs.stealth) != 1 {
		t.Errorf("stealth count = %d, want 1", len(cs.stealth))
	}

	if len(cs.cheating) != 2 {
		t.Errorf("cheating count = %d, want 2", len(cs.cheating))
	}

	// The invalid regex pattern falls back to literal.
	var hasLiteral bool
	for _, cp := range cs.suspicious {
		if cp.literal == "[" {
			hasLiteral = true
		}
	}
	if !hasLiteral {
		t.Error("expected invalid regex to fall back to literal")
	}
}

func TestScanExtensionFiles(t *testing.T) {
	dir := t.TempDir()

	// NOTE: eval() appears below as a test pattern for security scanning detection, not executable code.
	jsContent := `
		var x = eval("1+1");
		chrome.contentProtection = true;
		interview assistant tool
	`
	if err := os.WriteFile(filepath.Join(dir, "app.js"), []byte(jsContent), 0o644); err != nil {
		t.Fatal(err)
	}

	m := &manifest.Manifest{
		Extension: manifest.ExtensionConfig{
			SuspiciousPatterns: []manifest.SuspiciousPattern{
				{Name: "eval-use", Description: "Dynamic eval", Patterns: []string{`eval\(`}, Risk: "HIGH"},
			},
			StealthPatterns: []manifest.StealthPattern{
				{Name: "content-protection", Description: "Screen protection", Patterns: []string{`contentProtection`}, Risk: "CRITICAL"},
			},
			CheatingKeywords: []string{"interview"},
		},
		RiskScoring: manifest.RiskConfig{
			Weights: map[string]int{"HIGH": 20, "CRITICAL": 50},
		},
	}

	cs := newCompiledScanner(m)
	info := &ExtensionInfo{
		Name:        "Test Extension",
		Description: "An interview prep tool",
		Path:        dir,
	}

	cs.scanExtensionFiles(info)

	if len(info.CodeFindings) == 0 {
		t.Error("expected at least one code finding")
	}

	if len(info.StealthFlags) == 0 {
		t.Error("expected at least one stealth finding")
	}

	if len(info.CheatingFlags) == 0 {
		t.Error("expected at least one cheating flag")
	}
}

func TestScanExtensionFilesLiteralPattern(t *testing.T) {
	dir := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir, "bg.js"), []byte(`document.write("hello");`), 0o644); err != nil {
		t.Fatal(err)
	}

	m := &manifest.Manifest{
		Extension: manifest.ExtensionConfig{
			SuspiciousPatterns: []manifest.SuspiciousPattern{
				// Use an invalid regex so it falls back to literal matching.
				{Name: "doc-write", Description: "Injects HTML", Patterns: []string{"["}, Risk: "MEDIUM"},
			},
			StealthPatterns: []manifest.StealthPattern{
				{Name: "stealth-lit", Description: "Stealth literal", Patterns: []string{"["}, Risk: "HIGH"},
			},
			CheatingKeywords: []string{},
		},
		RiskScoring: manifest.RiskConfig{
			Weights: map[string]int{"MEDIUM": 10},
		},
	}

	cs := newCompiledScanner(m)
	info := &ExtensionInfo{Path: dir}
	cs.scanExtensionFiles(info)
	// Test completes without panic; literal-match paths are exercised.
}

func TestScanExtensionFilesCheatingInMetadata(t *testing.T) {
	dir := t.TempDir()

	// No JS files — cheating keyword must be caught from name/description.
	m := &manifest.Manifest{
		Extension: manifest.ExtensionConfig{
			CheatingKeywords: []string{"autocomplete"},
		},
		RiskScoring: manifest.RiskConfig{Weights: map[string]int{}},
	}

	cs := newCompiledScanner(m)
	info := &ExtensionInfo{
		Name:        "autocomplete helper",
		Description: "Helps with coding",
		Path:        dir,
	}

	cs.scanExtensionFiles(info)

	if len(info.CheatingFlags) == 0 {
		t.Error("expected cheating flag from metadata")
	}

	if !strings.Contains(info.CheatingFlags[0], "metadata:") {
		t.Errorf("expected metadata prefix, got %q", info.CheatingFlags[0])
	}
}

func TestAnalyzeExtensionFull(t *testing.T) {
	dir := t.TempDir()

	m := ChromeManifest{
		ManifestVersion: 3,
		Name:            "Full Analysis Ext",
		Version:         "2.0.0",
		Permissions:     []any{"tabs"},
	}

	data, _ := json.Marshal(m)
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}

	info, err := ParseExtension(dir, "full-id", "chrome", "Default")
	if err != nil {
		t.Fatalf("ParseExtension: %v", err)
	}

	mf := &manifest.Manifest{
		Extension: manifest.ExtensionConfig{
			DangerousPermissions: []manifest.ExtPermissionRule{
				{Permission: "tabs", Risk: "HIGH"},
			},
		},
		RiskScoring: manifest.RiskConfig{
			Weights: map[string]int{"HIGH": 20, "CRITICAL": 50, "MEDIUM": 10, "LOW": 2, "UNKNOWN": 5},
		},
	}

	analyzeExtensionFull(info, mf, false)

	if info.RiskScore == 0 {
		t.Error("expected non-zero risk score after full analysis")
	}

	if info.Permissions.ByRisk == nil {
		t.Error("expected ByRisk to be populated")
	}
}

func TestAnalyzeSingleExtensionFromDirectory(t *testing.T) {
	dir := t.TempDir()

	m := ChromeManifest{
		ManifestVersion: 3,
		Name:            "Single Ext",
		Version:         "1.0.0",
		Permissions:     []any{"storage"},
	}

	data, _ := json.Marshal(m)
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}

	mf := &manifest.Manifest{
		Extension: manifest.ExtensionConfig{
			DangerousPermissions: []manifest.ExtPermissionRule{
				{Permission: "storage", Risk: "LOW"},
			},
		},
		RiskScoring: manifest.RiskConfig{
			Weights: map[string]int{"LOW": 2, "HIGH": 20, "CRITICAL": 50, "MEDIUM": 10, "UNKNOWN": 5},
		},
	}

	info, err := AnalyzeSingleExtension(mf, dir, "", false)
	if err != nil {
		t.Fatalf("AnalyzeSingleExtension: %v", err)
	}

	if info.Name != "Single Ext" {
		t.Errorf("Name = %q, want %q", info.Name, "Single Ext")
	}

	if info.SourceType != "directory" {
		t.Errorf("SourceType = %q, want %q", info.SourceType, "directory")
	}
}

func TestAnalyzeSingleExtensionFromZIP(t *testing.T) {
	m := ChromeManifest{
		ManifestVersion: 2,
		Name:            "ZIP Ext",
		Version:         "1.0.0",
	}

	manifestData, _ := json.Marshal(m)
	zipData := buildZIPWithFiles(t, map[string]string{
		"manifest.json": string(manifestData),
	})

	zipPath := filepath.Join(t.TempDir(), "myext.zip")
	if err := os.WriteFile(zipPath, zipData, 0o644); err != nil {
		t.Fatal(err)
	}

	mf := &manifest.Manifest{
		RiskScoring: manifest.RiskConfig{
			Weights: map[string]int{"HIGH": 20, "CRITICAL": 50, "MEDIUM": 10, "LOW": 2, "UNKNOWN": 5},
		},
	}

	info, err := AnalyzeSingleExtension(mf, zipPath, "", false)
	if err != nil {
		t.Fatalf("AnalyzeSingleExtension from zip: %v", err)
	}

	if info.Name != "ZIP Ext" {
		t.Errorf("Name = %q, want %q", info.Name, "ZIP Ext")
	}

	if info.SourceType != "zip" {
		t.Errorf("SourceType = %q, want %q", info.SourceType, "zip")
	}
}

func TestAnalyzeSingleExtensionFromCRX(t *testing.T) {
	m := ChromeManifest{
		ManifestVersion: 3,
		Name:            "CRX Ext",
		Version:         "3.1.0",
	}

	manifestData, _ := json.Marshal(m)
	zipData := buildZIPWithFiles(t, map[string]string{
		"manifest.json": string(manifestData),
	})

	// Build a valid CRX v3 header.
	var buf bytes.Buffer
	buf.WriteString("Cr24")
	_ = binary.Write(&buf, binary.LittleEndian, uint32(3))
	_ = binary.Write(&buf, binary.LittleEndian, uint32(0)) // zero-length header
	buf.Write(zipData)

	crxPath := filepath.Join(t.TempDir(), "myext.crx")
	if err := os.WriteFile(crxPath, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	mf := &manifest.Manifest{
		RiskScoring: manifest.RiskConfig{
			Weights: map[string]int{"HIGH": 20, "CRITICAL": 50, "MEDIUM": 10, "LOW": 2, "UNKNOWN": 5},
		},
	}

	info, err := AnalyzeSingleExtension(mf, crxPath, "", false)
	if err != nil {
		t.Fatalf("AnalyzeSingleExtension from crx: %v", err)
	}

	if info.Name != "CRX Ext" {
		t.Errorf("Name = %q, want %q", info.Name, "CRX Ext")
	}
}

func TestAnalyzeSingleExtensionNotFound(t *testing.T) {
	mf := &manifest.Manifest{
		RiskScoring: manifest.RiskConfig{Weights: map[string]int{}},
	}

	_, err := AnalyzeSingleExtension(mf, "nonexistent-id-xyz", "", false)
	if err == nil {
		t.Fatal("expected error for nonexistent target")
	}
}

func TestAnalyzeSingleExtensionUnsupportedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ext.tar")
	if err := os.WriteFile(path, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}

	mf := &manifest.Manifest{
		RiskScoring: manifest.RiskConfig{Weights: map[string]int{}},
	}

	_, err := AnalyzeSingleExtension(mf, path, "", false)
	if err == nil {
		t.Fatal("expected error for unsupported file format")
	}
}

func TestExtractZIPEntries_PathTraversal(t *testing.T) {
	// Build a zip with a path-traversal entry; it should be silently skipped.
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)

	// Attempt directory traversal.
	f, err := w.Create("../evil.txt")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := f.Write([]byte("malicious")); err != nil {
		t.Fatal(err)
	}

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	destDir := t.TempDir()
	if err := extractZIPBytes(buf.Bytes(), destDir); err != nil {
		t.Fatalf("extractZIPBytes: %v", err)
	}

	// Confirm the traversal target was not written.
	parentFile := filepath.Join(filepath.Dir(destDir), "evil.txt")
	if _, err := os.Stat(parentFile); err == nil {
		t.Error("path traversal file should not have been created")
	}
}

func TestExtractZIPEntries_DirectoryEntry(t *testing.T) {
	// Build a zip that contains an explicit directory entry.
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)

	if _, err := w.Create("subdir/"); err != nil {
		t.Fatal(err)
	}

	f, err := w.Create("subdir/file.txt")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := f.Write([]byte("content")); err != nil {
		t.Fatal(err)
	}

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	destDir := t.TempDir()
	if err := extractZIPBytes(buf.Bytes(), destDir); err != nil {
		t.Fatalf("extractZIPBytes: %v", err)
	}

	if _, err := os.Stat(filepath.Join(destDir, "subdir", "file.txt")); err != nil {
		t.Errorf("expected subdir/file.txt: %v", err)
	}
}

func TestResolveAnalysisTarget_Directory(t *testing.T) {
	dir := t.TempDir()

	resolved, err := resolveAnalysisTarget(dir, "")
	if err != nil {
		t.Fatalf("resolveAnalysisTarget: %v", err)
	}

	if resolved.SourceType != "directory" {
		t.Errorf("SourceType = %q, want %q", resolved.SourceType, "directory")
	}

	if resolved.Path != dir {
		t.Errorf("Path = %q, want %q", resolved.Path, dir)
	}
}

func TestResolveAnalysisTarget_Package(t *testing.T) {
	m := ChromeManifest{
		ManifestVersion: 3,
		Name:            "Pkg Ext",
		Version:         "1.0.0",
	}

	manifestData, _ := json.Marshal(m)
	zipData := buildZIPWithFiles(t, map[string]string{
		"manifest.json": string(manifestData),
	})

	zipPath := filepath.Join(t.TempDir(), "pkg.zip")
	if err := os.WriteFile(zipPath, zipData, 0o644); err != nil {
		t.Fatal(err)
	}

	resolved, err := resolveAnalysisTarget(zipPath, "")
	if err != nil {
		t.Fatalf("resolveAnalysisTarget: %v", err)
	}

	defer resolved.Cleanup()

	if resolved.SourceType != "zip" {
		t.Errorf("SourceType = %q, want %q", resolved.SourceType, "zip")
	}

	if resolved.ID != "pkg" {
		t.Errorf("ID = %q, want %q", resolved.ID, "pkg")
	}
}

func TestResolveAnalysisTarget_UnsupportedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ext.tar")
	if err := os.WriteFile(path, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := resolveAnalysisTarget(path, "")
	if err == nil {
		t.Fatal("expected error for unsupported file target")
	}
}

func TestResolveAnalysisTarget_MissingID(t *testing.T) {
	_, err := resolveAnalysisTarget("nonexistent-extension-id-xyz", "")
	if err == nil {
		t.Fatal("expected error for missing extension ID")
	}
}

func TestExtractExtensionData(t *testing.T) {
	dir := t.TempDir()

	m := ChromeManifest{
		ManifestVersion: 3,
		Name:            "Extract Test Ext",
		Version:         "1.0.0",
		Permissions:     []any{"tabs"},
	}

	data, _ := json.Marshal(m)
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(dir, "bg.js"), []byte("console.log('bg');"), 0o644); err != nil {
		t.Fatal(err)
	}

	outputDir := filepath.Join(t.TempDir(), "out")
	mf := &manifest.Manifest{
		Extension: manifest.ExtensionConfig{
			DangerousPermissions: []manifest.ExtPermissionRule{
				{Permission: "tabs", Risk: "HIGH"},
			},
		},
		RiskScoring: manifest.RiskConfig{
			Weights: map[string]int{"HIGH": 20, "CRITICAL": 50, "MEDIUM": 10, "LOW": 2, "UNKNOWN": 5},
		},
	}

	result, err := ExtractExtensionData(mf, dir, "", outputDir, false)
	if err != nil {
		t.Fatalf("ExtractExtensionData: %v", err)
	}

	if result.Analysis == nil {
		t.Fatal("Analysis should not be nil")
	}

	if result.Analysis.Name != "Extract Test Ext" {
		t.Errorf("Analysis.Name = %q, want %q", result.Analysis.Name, "Extract Test Ext")
	}

	if result.SourceType != "directory" {
		t.Errorf("SourceType = %q, want %q", result.SourceType, "directory")
	}

	if _, err := os.Stat(result.AnalysisPath); err != nil {
		t.Errorf("analysis.json not created: %v", err)
	}

	if _, err := os.Stat(result.ReportPath); err != nil {
		t.Errorf("REPORT.md not created: %v", err)
	}

	if _, err := os.Stat(result.FilesDir); err != nil {
		t.Errorf("files dir not created: %v", err)
	}
}

func TestExtractExtensionDataEmptyOutputDir(t *testing.T) {
	mf := &manifest.Manifest{
		RiskScoring: manifest.RiskConfig{Weights: map[string]int{}},
	}

	_, err := ExtractExtensionData(mf, t.TempDir(), "", "", false)
	if err == nil {
		t.Fatal("expected error for empty output directory")
	}
}

func TestAnalyzeExtensionFullVerbose(t *testing.T) {
	dir := t.TempDir()

	m := ChromeManifest{
		ManifestVersion: 3,
		Name:            "Verbose Ext",
		Version:         "1.0.0",
		Permissions:     []any{"tabs", "debugger"},
	}

	data, _ := json.Marshal(m)
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}

	info, err := ParseExtension(dir, "verbose-id", "chrome", "Default")
	if err != nil {
		t.Fatalf("ParseExtension: %v", err)
	}

	mf := &manifest.Manifest{
		Extension: manifest.ExtensionConfig{
			DangerousPermissions: []manifest.ExtPermissionRule{
				{Permission: "tabs", Risk: "HIGH"},
				{Permission: "debugger", Risk: "CRITICAL"},
			},
		},
		RiskScoring: manifest.RiskConfig{
			Weights: map[string]int{"HIGH": 20, "CRITICAL": 50, "MEDIUM": 10, "LOW": 2, "UNKNOWN": 5},
		},
	}

	// verbose=true exercises the Printf branches in analyzeExtensionFull.
	analyzeExtensionFull(info, mf, true)

	if info.RiskLevel != "HIGH" && info.RiskLevel != "CRITICAL" {
		t.Errorf("RiskLevel = %q, want HIGH or CRITICAL", info.RiskLevel)
	}
}

func TestScanAllExtensionsWithFakeProfile(t *testing.T) {
	// Build a fake browser profile directory structure in temp.
	baseDir := t.TempDir()
	defaultDir := filepath.Join(baseDir, "Default")
	extDir := filepath.Join(defaultDir, "Extensions")
	extID := "aabbccddaabbccddaabbccddaabbccdd"
	versionDir := filepath.Join(extDir, extID, "1.0.0")

	if err := os.MkdirAll(versionDir, 0o755); err != nil {
		t.Fatal(err)
	}

	m := ChromeManifest{
		ManifestVersion: 3,
		Name:            "Scan Test Ext",
		Version:         "1.0.0",
		Permissions:     []any{"tabs"},
	}

	data, _ := json.Marshal(m)
	if err := os.WriteFile(filepath.Join(versionDir, "manifest.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}

	mf := &manifest.Manifest{
		Extension: manifest.ExtensionConfig{
			DangerousPermissions: []manifest.ExtPermissionRule{
				{Permission: "tabs", Risk: "HIGH"},
			},
			CheatingKeywords: []string{"interview"},
		},
		RiskScoring: manifest.RiskConfig{
			Weights: map[string]int{"HIGH": 20, "CRITICAL": 50, "MEDIUM": 10, "LOW": 2, "UNKNOWN": 5},
		},
	}

	// Inject a fake browser profile by calling internal helpers directly.
	// countExtensions and ParseExtension are exercised here.
	count := countExtensions(extDir)
	if count != 1 {
		t.Fatalf("countExtensions = %d, want 1", count)
	}

	info, err := ParseExtension(filepath.Join(extDir, extID), extID, "chrome", "Default")
	if err != nil {
		t.Fatalf("ParseExtension: %v", err)
	}

	scanner := newCompiledScanner(mf)
	AnalyzePermissions(info, scanner.permRules)
	scanner.scanExtensionFiles(info)
	enrichExtensionData(info)
	CalculateRiskScore(info, scanner.weights)

	if info.Name != "Scan Test Ext" {
		t.Errorf("Name = %q, want %q", info.Name, "Scan Test Ext")
	}

	if info.RiskScore == 0 {
		t.Error("expected non-zero risk score")
	}
}

func TestFindLatestVersionMultipleSubdirs(t *testing.T) {
	dir := t.TempDir()

	// Create two version subdirs; the second one alphabetically should be returned.
	for _, name := range []string{"1.0.0", "2.0.0"} {
		vDir := filepath.Join(dir, name)
		if err := os.MkdirAll(vDir, 0o755); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(filepath.Join(vDir, "manifest.json"), []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	got, err := findLatestVersion(dir)
	if err != nil {
		t.Fatalf("findLatestVersion: %v", err)
	}

	// Both dirs have manifests; the result must be one of the valid version dirs.
	if !strings.HasSuffix(got, "2.0.0") {
		t.Errorf("findLatestVersion() = %q, want path ending in 2.0.0", got)
	}
}

func TestFindLatestVersionFallsBackToFindManifest(t *testing.T) {
	// Create a structure where the version dir itself has no manifest.json
	// but a sub-sub-directory does.
	dir := t.TempDir()
	vDir := filepath.Join(dir, "1.0.0")
	deepDir := filepath.Join(vDir, "app")

	if err := os.MkdirAll(deepDir, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(deepDir, "manifest.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := findLatestVersion(dir)
	if err != nil {
		t.Fatalf("findLatestVersion: %v", err)
	}

	if got != deepDir {
		t.Errorf("findLatestVersion() = %q, want %q", got, deepDir)
	}
}

func TestDiscoverProfiles(t *testing.T) {
	t.Run("finds Default and Profile N", func(t *testing.T) {
		dir := t.TempDir()
		for _, name := range []string{"Default", "Profile 1", "Profile 2", "Cache"} {
			if err := os.MkdirAll(filepath.Join(dir, name), 0o755); err != nil {
				t.Fatal(err)
			}
		}

		profiles := discoverProfiles(dir)

		found := map[string]bool{}
		for _, p := range profiles {
			found[p] = true
		}

		if !found["Default"] {
			t.Error("expected Default profile")
		}

		if !found["Profile 1"] {
			t.Error("expected Profile 1")
		}

		if !found["Profile 2"] {
			t.Error("expected Profile 2")
		}

		if found["Cache"] {
			t.Error("Cache should not be in profiles")
		}
	})

	t.Run("opera-style falls back to dot", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dir, "Extensions"), 0o755); err != nil {
			t.Fatal(err)
		}

		profiles := discoverProfiles(dir)
		if len(profiles) != 1 || profiles[0] != "." {
			t.Errorf("profiles = %v, want [.]", profiles)
		}
	})
}

// buildMinimalZIP creates a minimal valid ZIP archive.
func buildMinimalZIP(t *testing.T) []byte {
	t.Helper()

	return buildZIPWithFiles(t, map[string]string{"test.txt": "hello"})
}

// buildZIPWithFiles creates a ZIP archive containing the given files.
func buildZIPWithFiles(t *testing.T, files map[string]string) []byte {
	t.Helper()

	var buf bytes.Buffer
	w := zip.NewWriter(&buf)

	for name, content := range files {
		f, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}

		if _, err := f.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	return buf.Bytes()
}

func TestCopyFile(t *testing.T) {
	t.Run("Normal", func(t *testing.T) {
		srcDir := t.TempDir()
		dstDir := t.TempDir()

		srcPath := filepath.Join(srcDir, "source.txt")
		dstPath := filepath.Join(dstDir, "dest.txt")
		content := "hello world content"

		if err := os.WriteFile(srcPath, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}

		if err := copyFile(srcPath, dstPath); err != nil {
			t.Fatalf("copyFile: %v", err)
		}

		got, err := os.ReadFile(dstPath)
		if err != nil {
			t.Fatalf("read dest: %v", err)
		}

		if string(got) != content {
			t.Errorf("content = %q, want %q", string(got), content)
		}
	})

	t.Run("SourceMissing", func(t *testing.T) {
		dstPath := filepath.Join(t.TempDir(), "dest.txt")

		err := copyFile("/nonexistent/path/file.txt", dstPath)
		if err == nil {
			t.Fatal("expected error for missing source")
		}
	})
}

func TestCopyExtensionDir(t *testing.T) {
	srcDir := t.TempDir()
	dstDir := t.TempDir()

	// Create manifest.json
	if err := os.WriteFile(filepath.Join(srcDir, "manifest.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Create js/content.js
	jsDir := filepath.Join(srcDir, "js")
	if err := os.MkdirAll(jsDir, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(jsDir, "content.js"), []byte(`console.log("test")`), 0o644); err != nil {
		t.Fatal(err)
	}

	// Create _metadata/verified_contents.json (should be skipped)
	metaDir := filepath.Join(srcDir, "_metadata")
	if err := os.MkdirAll(metaDir, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(metaDir, "verified_contents.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := copyExtensionDir(srcDir, dstDir); err != nil {
		t.Fatalf("copyExtensionDir: %v", err)
	}

	// Verify manifest.json exists
	if _, err := os.Stat(filepath.Join(dstDir, "manifest.json")); err != nil {
		t.Errorf("manifest.json should exist in dest: %v", err)
	}

	// Verify js/content.js exists
	if _, err := os.Stat(filepath.Join(dstDir, "js", "content.js")); err != nil {
		t.Errorf("js/content.js should exist in dest: %v", err)
	}

	// Verify _metadata was skipped
	if _, err := os.Stat(filepath.Join(dstDir, "_metadata")); err == nil {
		t.Error("_metadata directory should not exist in dest")
	}
}

func TestBeautifyJSFiles(t *testing.T) {
	dir := t.TempDir()

	// Create a minified JS file (single long line, avg > 200)
	longLine := strings.Repeat("var a=1;var b=2;var c=3;", 20)
	if err := os.WriteFile(filepath.Join(dir, "minified.js"), []byte(longLine), 0o644); err != nil {
		t.Fatal(err)
	}

	// Create an already-formatted JS file (short lines)
	formatted := "var x = 1;\nvar y = 2;\nvar z = 3;\nconsole.log(x);\n"
	if err := os.WriteFile(filepath.Join(dir, "already_formatted.js"), []byte(formatted), 0o644); err != nil {
		t.Fatal(err)
	}

	// Create a non-JS file (should be skipped)
	if err := os.WriteFile(filepath.Join(dir, "style.css"), []byte("body { margin: 0; }"), 0o644); err != nil {
		t.Fatal(err)
	}

	count := beautifyJSFiles(dir, false)
	if count != 1 {
		t.Errorf("beautifyJSFiles count = %d, want 1", count)
	}
}

func TestBeautifyJSFiles_LargeFileSkipped(t *testing.T) {
	dir := t.TempDir()

	// Create a JS file > 5MB
	largeContent := strings.Repeat("x", 6*1024*1024)
	if err := os.WriteFile(filepath.Join(dir, "huge.js"), []byte(largeContent), 0o644); err != nil {
		t.Fatal(err)
	}

	count := beautifyJSFiles(dir, false)
	if count != 0 {
		t.Errorf("beautifyJSFiles count = %d, want 0 (large file should be skipped)", count)
	}
}

func TestGenerateReport(t *testing.T) {
	// NOTE: "eval()" appears here as a test pattern for security scanning detection,
	// not as executable code. This is a security research tool that detects dangerous patterns.
	info := &ExtensionInfo{
		Name:        "Test Extension",
		ID:          "test-ext-id",
		Version:     "1.0.0",
		ManifestVer: 3,
		Browser:     "chrome",
		Profile:     "Default",
		Path:        "/tmp/ext",
		RiskLevel:   "HIGH",
		RiskScore:   75,
		Permissions: PermissionAnalysis{
			All:    []string{"tabs", "storage"},
			ByRisk: map[string][]string{"HIGH": {"tabs"}, "LOW": {"storage"}},
			Hosts:  []string{"<all_urls>"},
		},
		ContentScripts: []ContentScript{
			{Matches: []string{"<all_urls>"}, RunAt: "document_idle", JS: []string{"content.js"}, CSS: []string{"style.css"}},
		},
		CodeFindings: []CodeFinding{
			{Risk: "HIGH", Pattern: "eval()", File: "content.js", Line: 42, Context: "eval(data)"},
		},
		StealthFlags: []StealthFinding{
			{Risk: "HIGH", Name: "Content Protection", Description: "Hides from screen capture", File: "background.js", Evidence: "setContentProtection(true)"},
		},
		CheatingFlags: []string{"interview assistance detected"},
	}

	dir := t.TempDir()
	generateReport(info, dir, 3)

	data, err := os.ReadFile(filepath.Join(dir, "REPORT.md"))
	if err != nil {
		t.Fatalf("read REPORT.md: %v", err)
	}

	report := string(data)

	for _, want := range []string{
		"Test Extension",
		"test-ext-id",
		"1.0.0",
		"chrome",
		"HIGH",
		"tabs",
		"<all_urls>",
		"eval()",
		"content.js:42",
		"Content Protection",
		"interview assistance",
	} {
		if !strings.Contains(report, want) {
			t.Errorf("REPORT.md missing %q", want)
		}
	}
}

func TestGenerateSummary(t *testing.T) {
	dir := t.TempDir()

	res := &ExportResult{
		OutputDir: dir,
		Total:     3,
		Exported:  2,
		Skipped:   1,
		Extensions: []ExtensionInfo{
			{Name: "Dangerous Ext", Browser: "chrome", RiskLevel: "CRITICAL", RiskScore: 90, Permissions: PermissionAnalysis{All: []string{"tabs"}}, CodeFindings: []CodeFinding{{}}},
			{Name: "Safe Ext", Browser: "firefox", RiskLevel: "LOW", RiskScore: 10, Permissions: PermissionAnalysis{All: []string{"storage"}}},
			{Name: fmt.Sprintf("%s Long Name", strings.Repeat("A", 50)), Browser: "edge", RiskLevel: "MEDIUM", RiskScore: 50, Permissions: PermissionAnalysis{All: []string{"tabs", "cookies"}}},
		},
		Browsers: []BrowserProfile{
			{Browser: "chrome", Profile: "Default", ExtCount: 2},
			{Browser: "firefox", Profile: "default-release", ExtCount: 1},
		},
	}

	riskSummary := map[string]int{"CRITICAL": 1, "HIGH": 0, "MEDIUM": 1, "LOW": 1}

	generateSummary(res, riskSummary)

	data, err := os.ReadFile(filepath.Join(dir, "SUMMARY.md"))
	if err != nil {
		t.Fatalf("read SUMMARY.md: %v", err)
	}

	summary := string(data)

	for _, want := range []string{
		"Extension Export Summary",
		"Skipped:** 1",
		"CRITICAL | 1",
		"chrome",
		"firefox",
		"Dangerous Ext",
		"...",
		"Top Risk Extensions",
	} {
		if !strings.Contains(summary, want) {
			t.Errorf("SUMMARY.md missing %q", want)
		}
	}
}

// injectFakeBrowser temporarily replaces knownBrowsers with a single entry
// pointing at basePath, runs fn, then restores the original slice.
func injectFakeBrowser(t *testing.T, name, basePath string, fn func()) {
	t.Helper()

	orig := knownBrowsers
	knownBrowsers = []browserDef{
		{
			Name:    name,
			Linux:   []string{basePath},
			Windows: []string{basePath},
			Darwin:  []string{basePath},
		},
	}

	defer func() { knownBrowsers = orig }()

	fn()
}

// buildFakeProfile creates the directory structure that DiscoverBrowsers
// and ScanAllExtensions expect:
//
//	basePath/Default/Extensions/<extID>/<version>/manifest.json
//
// It returns the extension ID used.
func buildFakeProfile(t *testing.T, basePath string, manifest ChromeManifest) string {
	t.Helper()

	extID := "aaaabbbbccccddddaaaabbbbccccdddd"
	versionDir := filepath.Join(basePath, "Default", "Extensions", extID, "1.0.0")

	if err := os.MkdirAll(versionDir, 0o755); err != nil {
		t.Fatal(err)
	}

	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(versionDir, "manifest.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}

	return extID
}

func TestScanAllExtensions(t *testing.T) {
	baseDir := t.TempDir()

	m := ChromeManifest{
		ManifestVersion: 3,
		Name:            "Scan All Test Ext",
		Version:         "1.0.0",
		Permissions:     []any{"tabs"},
	}

	buildFakeProfile(t, baseDir, m)

	mf := &manifest.Manifest{
		Extension: manifest.ExtensionConfig{
			DangerousPermissions: []manifest.ExtPermissionRule{
				{Permission: "tabs", Risk: "HIGH"},
			},
		},
		RiskScoring: manifest.RiskConfig{
			Weights: map[string]int{"HIGH": 20, "CRITICAL": 50, "MEDIUM": 10, "LOW": 2, "UNKNOWN": 5},
		},
	}

	var result *ScanResult

	injectFakeBrowser(t, "chrome", baseDir, func() {
		result = ScanAllExtensions(mf, "", false)
	})

	if result == nil {
		t.Fatal("ScanAllExtensions returned nil")
	}

	if result.TotalExts != 1 {
		t.Errorf("TotalExts = %d, want 1", result.TotalExts)
	}

	if len(result.Extensions) != 1 {
		t.Fatalf("Extensions len = %d, want 1", len(result.Extensions))
	}

	if result.Extensions[0].Name != "Scan All Test Ext" {
		t.Errorf("Extensions[0].Name = %q, want %q", result.Extensions[0].Name, "Scan All Test Ext")
	}

	if result.RiskSummary["HIGH"] == 0 && result.RiskSummary["MEDIUM"] == 0 {
		t.Error("expected non-zero risk summary entry")
	}
}

func TestScanAllExtensionsVerbose(t *testing.T) {
	baseDir := t.TempDir()

	m := ChromeManifest{
		ManifestVersion: 3,
		Name:            "Verbose Scan Ext",
		Version:         "1.0.0",
	}

	buildFakeProfile(t, baseDir, m)

	mf := &manifest.Manifest{
		RiskScoring: manifest.RiskConfig{
			Weights: map[string]int{"HIGH": 20, "CRITICAL": 50, "MEDIUM": 10, "LOW": 2, "UNKNOWN": 5},
		},
	}

	injectFakeBrowser(t, "chrome", baseDir, func() {
		// verbose=true exercises the Printf branches in ScanAllExtensions.
		result := ScanAllExtensions(mf, "", true)
		if result.TotalExts != 1 {
			t.Errorf("TotalExts = %d, want 1", result.TotalExts)
		}
	})
}

func TestScanAllExtensionsFilterBrowser(t *testing.T) {
	baseDir := t.TempDir()

	m := ChromeManifest{
		ManifestVersion: 3,
		Name:            "Filter Test Ext",
		Version:         "1.0.0",
	}

	buildFakeProfile(t, baseDir, m)

	mf := &manifest.Manifest{
		RiskScoring: manifest.RiskConfig{
			Weights: map[string]int{"HIGH": 20},
		},
	}

	var result *ScanResult

	injectFakeBrowser(t, "chrome", baseDir, func() {
		// Filtering by a different browser name should return zero extensions.
		result = ScanAllExtensions(mf, "edge", false)
	})

	if result.TotalExts != 0 {
		t.Errorf("TotalExts = %d, want 0 when browser filter excludes everything", result.TotalExts)
	}
}

func TestScanAllExtensionsSkipsInvalidManifest(t *testing.T) {
	baseDir := t.TempDir()

	// Write a broken manifest so ParseExtension fails.
	extID := "invalidmanifestextid1234567890ab"
	versionDir := filepath.Join(baseDir, "Default", "Extensions", extID, "1.0.0")

	if err := os.MkdirAll(versionDir, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(versionDir, "manifest.json"), []byte("{bad json"), 0o644); err != nil {
		t.Fatal(err)
	}

	mf := &manifest.Manifest{
		RiskScoring: manifest.RiskConfig{Weights: map[string]int{}},
	}

	var result *ScanResult

	injectFakeBrowser(t, "chrome", baseDir, func() {
		// verbose=true so the skip path with Printf is covered.
		result = ScanAllExtensions(mf, "", true)
	})

	if result.TotalExts != 0 {
		t.Errorf("TotalExts = %d, want 0 for invalid manifests", result.TotalExts)
	}
}

func TestSearchExtensions(t *testing.T) {
	baseDir := t.TempDir()

	m := ChromeManifest{
		ManifestVersion: 3,
		Name:            "Search Target Ext",
		Version:         "1.0.0",
	}

	extID := buildFakeProfile(t, baseDir, m)
	versionDir := filepath.Join(baseDir, "Default", "Extensions", extID, "1.0.0")

	// Write a JS file containing a unique search term.
	jsContent := `var secret = "FINDME_TARGET_TOKEN";`
	if err := os.WriteFile(filepath.Join(versionDir, "app.js"), []byte(jsContent), 0o644); err != nil {
		t.Fatal(err)
	}

	var result *SearchResult

	injectFakeBrowser(t, "chrome", baseDir, func() {
		result = SearchExtensions("FINDME_TARGET_TOKEN", "")
	})

	if result == nil {
		t.Fatal("SearchExtensions returned nil")
	}

	if result.Pattern != "FINDME_TARGET_TOKEN" {
		t.Errorf("Pattern = %q, want %q", result.Pattern, "FINDME_TARGET_TOKEN")
	}

	if len(result.Matches) == 0 {
		t.Fatal("expected at least one match for FINDME_TARGET_TOKEN")
	}

	if result.Total == 0 {
		t.Error("expected Total > 0")
	}

	match := result.Matches[0]
	if match.Extension != "Search Target Ext" {
		t.Errorf("Match.Extension = %q, want %q", match.Extension, "Search Target Ext")
	}

	if match.Browser != "chrome" {
		t.Errorf("Match.Browser = %q, want %q", match.Browser, "chrome")
	}
}

func TestSearchExtensionsNoMatch(t *testing.T) {
	baseDir := t.TempDir()

	m := ChromeManifest{
		ManifestVersion: 3,
		Name:            "No Match Ext",
		Version:         "1.0.0",
	}

	extID := buildFakeProfile(t, baseDir, m)
	versionDir := filepath.Join(baseDir, "Default", "Extensions", extID, "1.0.0")

	if err := os.WriteFile(filepath.Join(versionDir, "bg.js"), []byte("console.log('hello');"), 0o644); err != nil {
		t.Fatal(err)
	}

	var result *SearchResult

	injectFakeBrowser(t, "chrome", baseDir, func() {
		result = SearchExtensions("XYZZY_NOTHING_HERE", "")
	})

	if len(result.Matches) != 0 {
		t.Errorf("expected zero matches, got %d", len(result.Matches))
	}
}

func TestSearchExtensionsFilterBrowser(t *testing.T) {
	baseDir := t.TempDir()

	m := ChromeManifest{
		ManifestVersion: 3,
		Name:            "Filter Browser Search Ext",
		Version:         "1.0.0",
	}

	extID := buildFakeProfile(t, baseDir, m)
	versionDir := filepath.Join(baseDir, "Default", "Extensions", extID, "1.0.0")

	if err := os.WriteFile(filepath.Join(versionDir, "bg.js"), []byte("FILTER_SEARCH_TOKEN"), 0o644); err != nil {
		t.Fatal(err)
	}

	var result *SearchResult

	injectFakeBrowser(t, "chrome", baseDir, func() {
		// Filtering by edge excludes the chrome browser above.
		result = SearchExtensions("FILTER_SEARCH_TOKEN", "edge")
	})

	if len(result.Matches) != 0 {
		t.Errorf("expected zero matches when browser filter excludes results, got %d", len(result.Matches))
	}
}

func TestHomeDir(t *testing.T) {
	// homeDir() must return a non-empty string on any supported platform.
	got := homeDir()
	if got == "" {
		t.Error("homeDir() returned empty string")
	}
}

func TestResolvePackageTargetEmptyBaseName(t *testing.T) {
	// Build a zip whose filename base is empty after stripping the extension.
	// This is synthetically impossible via normal OS paths, so we exercise the
	// fallback by creating a zip file named ".zip" inside a temp dir.
	zipData := buildZIPWithFiles(t, map[string]string{
		"manifest.json": `{"name":"dot"}`,
	})

	// Use a path where TrimSuffix leaves an empty string (".zip" -> "").
	// Write it to a temp dir as ".zip".
	tmpDir := t.TempDir()
	pkgPath := filepath.Join(tmpDir, ".zip")

	if err := os.WriteFile(pkgPath, zipData, 0o644); err != nil {
		t.Fatal(err)
	}

	resolved, err := resolvePackageTarget(pkgPath)
	if err != nil {
		t.Fatalf("resolvePackageTarget: %v", err)
	}

	defer resolved.Cleanup()

	// The fallback basename must be "extension".
	if resolved.ID != "extension" {
		t.Errorf("ID = %q, want %q", resolved.ID, "extension")
	}
}
