/*
Copyright (c) 2026 Security Research
*/
package autogen

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/inject"
	"github.com/inovacc/unravel-oss/pkg/jsdeob"
)

var update = flag.Bool("update", false, "regenerate snapshot golden files")

func loadReport(t *testing.T, path string) inject.ScanResult {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var r inject.ScanResult
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatalf("unmarshal %s: %v", path, err)
	}
	return r
}

func runSnapshot(t *testing.T, fixture string) {
	t.Helper()
	report := loadReport(t, filepath.Join("testdata", fixture))
	tmp := t.TempDir()
	res, err := Generate(report, tmp, Options{})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if len(res.Scripts) == 0 {
		t.Fatal("no scripts generated")
	}
	goldenDir := filepath.Join("testdata", "golden")
	if *update {
		if err := os.MkdirAll(goldenDir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, gs := range res.Scripts {
		// Defense in depth: lint each generated JS.
		jsBytes, err := os.ReadFile(gs.ScriptPath)
		if err != nil {
			t.Fatal(err)
		}
		if err := jsdeob.Lint(string(jsBytes)); err != nil {
			t.Errorf("generated JS for seam %s did not lint clean: %v", gs.SeamID, err)
		}
		if gs.Platform == "linux" && !strings.Contains(string(jsBytes), "preflight_failed") {
			t.Errorf("linux generated JS missing preflight_failed (seam %s)", gs.SeamID)
		}
		critBytes, err := os.ReadFile(gs.CriteriaPath)
		if err != nil {
			t.Fatal(err)
		}
		for _, pair := range []struct {
			name  string
			bytes []byte
		}{
			{filepath.Base(gs.ScriptPath), jsBytes},
			{filepath.Base(gs.CriteriaPath), critBytes},
		} {
			goldPath := filepath.Join(goldenDir, pair.name)
			if *update {
				if err := os.WriteFile(goldPath, pair.bytes, 0o644); err != nil {
					t.Fatal(err)
				}
				continue
			}
			want, err := os.ReadFile(goldPath)
			if err != nil {
				t.Fatalf("missing golden %s — run with -update first: %v", goldPath, err)
			}
			if !bytes.Equal(pair.bytes, want) {
				t.Errorf("snapshot mismatch for %s\n--- got ---\n%s\n--- want ---\n%s", pair.name, pair.bytes, want)
			}
		}
	}
}

func TestSnapshot_Windows(t *testing.T)  { runSnapshot(t, "windows-seamreport.json") }
func TestSnapshot_Linux(t *testing.T)    { runSnapshot(t, "linux-seamreport.json") }
func TestSnapshot_MacOS(t *testing.T)    { runSnapshot(t, "macos-seamreport.json") }
func TestSnapshot_Combined(t *testing.T) { runSnapshot(t, "combined-seamreport.json") }
