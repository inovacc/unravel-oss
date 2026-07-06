/*
Copyright (c) 2026 Security Research
*/

package udf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDiscoverUDFDefault(t *testing.T) {
	// Isolate LOCALAPPDATA so it doesn't contribute a real candidate.
	t.Setenv("LOCALAPPDATA", t.TempDir())

	tmp := t.TempDir()
	exePath := filepath.Join(tmp, "MyApp.exe")
	if err := os.WriteFile(exePath, []byte{0}, 0o600); err != nil {
		t.Fatal(err)
	}
	// Create sibling .WebView2/EBWebView
	ebDir := filepath.Join(tmp, "MyApp.exe.WebView2", "EBWebView")
	if err := os.MkdirAll(ebDir, 0o700); err != nil {
		t.Fatal(err)
	}

	got, err := DiscoverUDFs(exePath)
	if err != nil {
		t.Fatalf("DiscoverUDFs: %v", err)
	}
	var found bool
	for _, u := range got {
		if u.Source == "default" {
			found = true
			if !u.Exists {
				t.Errorf("default candidate: Exists=false, want true")
			}
			if !strings.HasSuffix(filepath.ToSlash(u.Path), "EBWebView") {
				t.Errorf("default path %q does not end in EBWebView", u.Path)
			}
		}
	}
	if !found {
		t.Fatalf("no default-source candidate in %+v", got)
	}
}

func TestDiscoverUDFMissing(t *testing.T) {
	t.Setenv("LOCALAPPDATA", t.TempDir())
	tmp := t.TempDir()
	exePath := filepath.Join(tmp, "MyApp.exe")
	if err := os.WriteFile(exePath, []byte{0}, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := DiscoverUDFs(exePath)
	if err != nil {
		t.Fatalf("DiscoverUDFs: %v", err)
	}
	// Every candidate must have Exists=false (or zero)
	for _, u := range got {
		if u.Exists {
			t.Errorf("expected all candidates absent, got existing %+v", u)
		}
	}
}

func TestDiscoverUDFLocalAppData(t *testing.T) {
	lad := t.TempDir()
	t.Setenv("LOCALAPPDATA", lad)

	tmp := t.TempDir()
	exePath := filepath.Join(tmp, "ProductName.exe")
	if err := os.WriteFile(exePath, []byte{0}, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(lad, "ProductName", "EBWebView"), 0o700); err != nil {
		t.Fatal(err)
	}

	got, err := DiscoverUDFs(exePath)
	if err != nil {
		t.Fatalf("DiscoverUDFs: %v", err)
	}
	var hit bool
	for _, u := range got {
		if u.Source == "localappdata" && u.Exists {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("no existing localappdata candidate in %+v", got)
	}
}

func TestDiscoverUDFEmptyPath(t *testing.T) {
	got, err := DiscoverUDFs("")
	if err != nil {
		t.Fatalf("DiscoverUDFs(empty): %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty slice, got %+v", got)
	}
}

func TestHasDotDot(t *testing.T) {
	cases := map[string]bool{
		"a/b/c":     false,
		"../evil":   true,
		"a/../b":    true,
		"a/b":       false,
		"..":        true,
		"/abs/path": false,
		"a/..b/c":   false, // not a segment
	}
	for p, want := range cases {
		if got := hasDotDot(p); got != want {
			t.Errorf("hasDotDot(%q)=%v want %v", p, got, want)
		}
	}
}
