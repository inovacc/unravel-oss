/*
Copyright (c) 2026 Security Research
*/

package webview2

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteCDPSourceSidecar_RoundTrip(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("LOCALAPPDATA", tmp)

	js := []CDPSrcEntry{{URL: "https://web.whatsapp.com/app.js", Source: "console.log(1)"}}
	css := []CDPSrcEntry{{URL: "https://web.whatsapp.com/app.css", Source: "body{color:red}"}}

	path, err := WriteCDPSourceSidecar("5319275A.WhatsAppDesktop", js, css)
	if err != nil {
		t.Fatalf("WriteCDPSourceSidecar: %v", err)
	}
	if path == "" {
		t.Fatal("expected non-empty path for non-empty input")
	}
	if !strings.HasPrefix(path, tmp) {
		t.Fatalf("path %q not under temp LOCALAPPDATA %q", path, tmp)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	var sc CDPSourceSidecar
	if err := json.Unmarshal(raw, &sc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if sc.PkgKey != "5319275A.WhatsAppDesktop" {
		t.Fatalf("pkg_key = %q", sc.PkgKey)
	}
	if sc.PulledAt.IsZero() {
		t.Fatal("PulledAt not set")
	}
	if len(sc.JS) != 1 || sc.JS[0].URL != js[0].URL || sc.JS[0].Source != js[0].Source {
		t.Fatalf("JS round-trip mismatch: %+v", sc.JS)
	}
	if len(sc.CSS) != 1 || sc.CSS[0].URL != css[0].URL || sc.CSS[0].Source != css[0].Source {
		t.Fatalf("CSS round-trip mismatch: %+v", sc.CSS)
	}
}

func TestWriteCDPSourceSidecar_HonestEmpty(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("LOCALAPPDATA", tmp)

	path, err := WriteCDPSourceSidecar("MSTeams", nil, nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if path != "" {
		t.Fatalf("expected empty path for honest-empty, got %q", path)
	}
	if _, statErr := os.Stat(CDPSourceSidecarPath("MSTeams")); !os.IsNotExist(statErr) {
		t.Fatalf("expected no file written, stat err = %v", statErr)
	}
}

func TestCDPSourceSidecarPath_Sanitizes(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("LOCALAPPDATA", tmp)

	p := CDPSourceSidecarPath(`..\..\evil/MSTeams`)
	if filepath.Clean(p) != p {
		t.Fatalf("path not clean: %q", p)
	}
	// The sanitized package-id segment must contain no traversal/separators.
	seg := filepath.Base(filepath.Dir(p))
	if strings.ContainsAny(seg, `/\`) || seg == ".." || seg == "." {
		t.Fatalf("pkg segment unsafe: %q (full %q)", seg, p)
	}
	rel, err := filepath.Rel(tmp, p)
	if err != nil {
		t.Fatalf("rel: %v", err)
	}
	if strings.HasPrefix(rel, "..") {
		t.Fatalf("path escapes base: rel=%q", rel)
	}
}
