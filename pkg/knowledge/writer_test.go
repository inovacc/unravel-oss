package knowledge

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWriteDirectory(t *testing.T) {
	dir := t.TempDir()

	r := &KnowledgeResult{
		AppName:    "TestApp",
		Framework:  "Electron",
		Version:    "1.0.0",
		AnalyzedAt: time.Now(),
		SourcePath: "/path/to/app",
		Communication: &CommunicationKnowledge{
			Endpoints: []Endpoint{
				{URL: "https://api.example.com/v1", Methods: []string{"GET", "POST"}, Purpose: "Main API"},
			},
			Protocols:          []string{"HTTPS", "WebSocket"},
			DataFormats:        []string{"JSON", "Protobuf"},
			CertificatePinning: true,
		},
		IPC: &IPCKnowledge{
			Channels: []IPCChannel{
				{Name: "main-to-renderer", Direction: "bidirectional", Privileged: true, RiskLevel: "high"},
			},
		},
		Security: &SecurityKnowledge{
			RiskScore: 75,
			RiskLevel: "HIGH",
			Settings: []SecuritySetting{
				{Name: "nodeIntegration", Value: "true", Safe: false, Comment: "Dangerous"},
			},
			Vulnerabilities: []string{"XSS via nodeIntegration"},
		},
	}

	if err := WriteDirectory(r, dir); err != nil {
		t.Fatalf("WriteDirectory: %v", err)
	}

	// manifest.json exists and is valid JSON
	data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatalf("read manifest.json: %v", err)
	}
	var manifest map[string]any
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("manifest.json not valid JSON: %v", err)
	}

	// subdirs exist
	for _, sub := range []string{"communication", "ipc", "security"} {
		info, err := os.Stat(filepath.Join(dir, sub))
		if err != nil {
			t.Fatalf("subdir %s missing: %v", sub, err)
		}
		if !info.IsDir() {
			t.Fatalf("%s is not a directory", sub)
		}
	}

	// communication/endpoints.json valid JSON
	data, err = os.ReadFile(filepath.Join(dir, "communication", "endpoints.json"))
	if err != nil {
		t.Fatalf("read endpoints.json: %v", err)
	}
	var endpoints []any
	if err := json.Unmarshal(data, &endpoints); err != nil {
		t.Fatalf("endpoints.json not valid JSON: %v", err)
	}

	// communication/protocols.md exists
	if _, err := os.Stat(filepath.Join(dir, "communication", "protocols.md")); err != nil {
		t.Fatalf("protocols.md missing: %v", err)
	}

	// security/risks.md exists
	if _, err := os.Stat(filepath.Join(dir, "security", "risks.md")); err != nil {
		t.Fatalf("risks.md missing: %v", err)
	}
}

func TestWriteDirectory_DataDir(t *testing.T) {
	dir := t.TempDir()

	r := &KnowledgeResult{
		AppName:    "DataApp",
		Framework:  "Electron",
		AnalyzedAt: time.Now(),
		DataDir: &DataDirKnowledge{
			Path: "/fake/appdata/DataApp",
			LocalStorage: &LocalStorageData{
				Origins: []StorageOrigin{
					{
						Origin: "https://app.example.com",
						Entries: []StorageEntry{
							{Key: "token", Value: "abc123"},
						},
					},
				},
				Stats: StorageStats{TotalEntries: 1, OriginCount: 1},
			},
			Cache: &CacheData{
				Format:     "simple",
				Domains:    map[string]int{"api.example.com": 5},
				Types:      map[string]int{"application/json": 3},
				EntryCount: 5,
				TotalSize:  1024,
			},
			Preferences: map[string]any{"profile": map[string]any{"name": "test"}},
		},
	}

	if err := WriteDirectory(r, dir); err != nil {
		t.Fatalf("WriteDirectory: %v", err)
	}

	// data/ subdir exists
	dataDir := filepath.Join(dir, "data")
	info, err := os.Stat(dataDir)
	if err != nil {
		t.Fatalf("data dir missing: %v", err)
	}
	if !info.IsDir() {
		t.Fatal("data is not a directory")
	}

	// Check all expected files
	for _, name := range []string{"local-storage.json", "cache-summary.json", "preferences.json", "overview.md"} {
		if _, err := os.Stat(filepath.Join(dataDir, name)); err != nil {
			t.Errorf("%s missing: %v", name, err)
		}
	}

	// Verify local-storage.json is valid JSON
	data, err := os.ReadFile(filepath.Join(dataDir, "local-storage.json"))
	if err != nil {
		t.Fatalf("read local-storage.json: %v", err)
	}
	var ls any
	if err := json.Unmarshal(data, &ls); err != nil {
		t.Fatalf("local-storage.json not valid JSON: %v", err)
	}
}

func TestWriteDirectory_Empty(t *testing.T) {
	dir := t.TempDir()

	r := &KnowledgeResult{
		AppName:    "EmptyApp",
		Framework:  "Tauri",
		AnalyzedAt: time.Now(),
	}

	if err := WriteDirectory(r, dir); err != nil {
		t.Fatalf("WriteDirectory: %v", err)
	}

	// manifest.json written
	data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatalf("read manifest.json: %v", err)
	}
	var manifest map[string]any
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("manifest.json not valid JSON: %v", err)
	}

	// no subdirectories for nil aspects
	for _, sub := range []string{"communication", "auth", "ui", "ipc", "security", "stealth", "telemetry", "source"} {
		if _, err := os.Stat(filepath.Join(dir, sub)); err == nil {
			t.Fatalf("subdir %s should not exist for nil aspect", sub)
		}
	}
}

func newKR(files ...SourceFile) *KnowledgeResult {
	return &KnowledgeResult{
		AppName:     "TestApp",
		Framework:   "electron",
		AnalyzedAt:  time.Now(),
		SourceFiles: files,
	}
}

func TestWriteDirectorySourcesComponentLayout(t *testing.T) {
	dir := t.TempDir()
	kr := newKR(
		SourceFile{Path: "src/auth/login.js", Content: []byte("// login"), BeautifyProvenance: "phase6-js"},
		SourceFile{Path: "src/lib/sentry.js", Content: []byte("// sentry init")},
	)
	if err := WriteDirectory(kr, dir); err != nil {
		t.Fatalf("WriteDirectory: %v", err)
	}

	wantFiles := []string{
		filepath.Join(dir, "sources", "auth", "login.js"),
		filepath.Join(dir, "sources", "auth", "login.js._meta.json"),
		filepath.Join(dir, "sources", "telemetry", "sentry.js"),
		filepath.Join(dir, "sources", "telemetry", "sentry.js._meta.json"),
	}
	for _, p := range wantFiles {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("missing %s: %v", p, err)
		}
	}
	// Legacy singular-source layout must NOT exist.
	if _, err := os.Stat(filepath.Join(dir, "source")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("legacy <dir>/source/ should not exist, err=%v", err)
	}
	// Empty-content entries should be skipped (no file).
	kr2 := newKR(SourceFile{Path: "src/api/empty.js", Content: nil})
	dir2 := t.TempDir()
	if err := WriteDirectory(kr2, dir2); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir2, "sources", "api", "empty.js")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("nil-content file should not be written: %v", err)
	}
}

func TestMetaJSONShape(t *testing.T) {
	dir := t.TempDir()
	kr := newKR(SourceFile{
		Path:               "src/auth/login.js",
		Content:            []byte("// login"),
		RawSourcePath:      "decompiled/auth/login.js",
		BeautifyProvenance: "phase6-js",
	})
	if err := WriteDirectory(kr, dir); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "sources", "auth", "login.js._meta.json"))
	if err != nil {
		t.Fatal(err)
	}
	var meta SourceMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if meta.Component != "auth" {
		t.Errorf("component: got %q want auth", meta.Component)
	}
	if meta.Classifier == "" {
		t.Errorf("classifier empty")
	}
	if meta.Confidence < 0 {
		t.Errorf("confidence negative: %v", meta.Confidence)
	}
	if meta.RawSourcePath != "decompiled/auth/login.js" {
		t.Errorf("raw_source_path: got %q", meta.RawSourcePath)
	}
	if meta.BeautifyProvenance != "phase6-js" {
		t.Errorf("beautify_provenance: got %q", meta.BeautifyProvenance)
	}
}

func TestManifestFilesInventory(t *testing.T) {
	dir := t.TempDir()
	kr := newKR(
		SourceFile{Path: "src/auth/login.js", Content: []byte("// l"), BeautifyProvenance: "phase6-js"},
		SourceFile{Path: "src/api/Client.ts", Content: []byte("// c")},
	)
	if err := WriteDirectory(kr, dir); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	if m.Version != 1 {
		t.Errorf("Version: got %d want 1", m.Version)
	}
	if len(m.Files) != 2 {
		t.Fatalf("files count: got %d want 2", len(m.Files))
	}
	wantLang := map[string]string{
		"sources/auth/login.js": "javascript",
		"sources/api/Client.ts": "typescript",
	}
	for _, f := range m.Files {
		if f.Component == "" || f.Path == "" {
			t.Errorf("empty fields in %+v", f)
		}
		if got := wantLang[f.Path]; got != f.SourceLanguage {
			t.Errorf("language for %s: got %q want %q", f.Path, f.SourceLanguage, got)
		}
	}
}

func TestWriteDirectoryRejectsTraversal(t *testing.T) {
	dir := t.TempDir()
	kr := newKR(SourceFile{Path: "../escape.js", Content: []byte("x")})
	err := WriteDirectory(kr, dir)
	if !errors.Is(err, errPathTraversal) {
		t.Fatalf("want errPathTraversal, got %v", err)
	}
	parent := filepath.Dir(dir)
	if _, err := os.Stat(filepath.Join(parent, "escape.js")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("escape file appeared: %v", err)
	}
}

func TestWriteDirectoryUnknownBucket(t *testing.T) {
	dir := t.TempDir()
	kr := newKR(SourceFile{Path: "src/zzz_xyz.go", Content: []byte("package zzz")})
	if err := WriteDirectory(kr, dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "sources", "unknown", "zzz_xyz.go")); err != nil {
		t.Fatalf("expected sources/unknown/ landing: %v", err)
	}
}

func TestEmittedFileBackCompatVersion(t *testing.T) {
	body := []byte(`{"app_name":"old","sections":{}}`)
	var m Manifest
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatal(err)
	}
	if m.Version != 0 {
		t.Errorf("legacy unmarshal: Version got %d want 0", m.Version)
	}
	if m.AppName != "old" {
		t.Errorf("AppName: %q", m.AppName)
	}
}
