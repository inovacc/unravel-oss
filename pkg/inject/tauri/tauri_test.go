/*
Copyright (c) 2026 Security Research
*/
package tauri

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/inject"
)

// copyFixture copies testdata/<name> to <dst>.
func copyFixture(t *testing.T, name, dst string) {
	t.Helper()
	src := filepath.Join("testdata", name)
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read fixture %s: %v", src, err)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(dst), err)
	}
	if err := os.WriteFile(dst, data, 0o644); err != nil {
		t.Fatalf("write %s: %v", dst, err)
	}
}

func TestDetect_TauriConfPresent(t *testing.T) {
	dir := t.TempDir()
	copyFixture(t, "tauri.conf.devtools.json", filepath.Join(dir, "tauri.conf.json"))
	if !(scanner{}).Detect(dir) {
		t.Fatalf("expected Detect=true with tauri.conf.json present")
	}
}

func TestDetect_CargoTomlTauriDep(t *testing.T) {
	dir := t.TempDir()
	copyFixture(t, "Cargo.toml.devtools-feature", filepath.Join(dir, "Cargo.toml"))
	if !(scanner{}).Detect(dir) {
		t.Fatalf("expected Detect=true with Cargo.toml referencing tauri")
	}
}

func TestDetect_NoSignals(t *testing.T) {
	dir := t.TempDir()
	if (scanner{}).Detect(dir) {
		t.Fatalf("expected Detect=false in empty dir")
	}
}

// findSeams returns all seams of kind k.
func findSeams(seams []inject.Seam, kind string) []inject.Seam {
	var out []inject.Seam
	for _, s := range seams {
		if s.Kind == kind {
			out = append(out, s)
		}
	}
	return out
}

func TestScan_DevtoolsFromConf(t *testing.T) {
	dir := t.TempDir()
	copyFixture(t, "tauri.conf.devtools.json", filepath.Join(dir, "tauri.conf.json"))

	seams, err := (scanner{}).Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	dev := findSeams(seams, "tauri-devtools")
	if len(dev) != 1 {
		t.Fatalf("expected 1 tauri-devtools seam, got %d (%+v)", len(dev), seams)
	}
	if dev[0].Confidence != inject.ConfidenceHigh {
		t.Fatalf("expected high confidence, got %s", dev[0].Confidence)
	}
	if dev[0].Framework != inject.FrameworkTauri {
		t.Fatalf("expected framework=tauri, got %s", dev[0].Framework)
	}
}

func TestScan_AllowlistKeysPerApi(t *testing.T) {
	dir := t.TempDir()
	copyFixture(t, "tauri.conf.allowlist.json", filepath.Join(dir, "tauri.conf.json"))

	seams, err := (scanner{}).Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	al := findSeams(seams, "tauri-allowlist")
	if len(al) < 3 {
		t.Fatalf("expected >=3 tauri-allowlist seams (fs.all, shell.open, http.scope), got %d (%+v)", len(al), seams)
	}
	for _, s := range al {
		if s.Confidence != inject.ConfidenceHigh {
			t.Fatalf("expected high confidence on allowlist seam, got %s (%+v)", s.Confidence, s)
		}
	}
}

func TestScan_CustomProtocol(t *testing.T) {
	dir := t.TempDir()
	copyFixture(t, "tauri.conf.protocol.json", filepath.Join(dir, "tauri.conf.json"))

	seams, err := (scanner{}).Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	p := findSeams(seams, "tauri-custom-protocol")
	if len(p) != 1 {
		t.Fatalf("expected 1 tauri-custom-protocol seam, got %d (%+v)", len(p), seams)
	}
}

func TestScan_DevtoolsFromCargoFeature(t *testing.T) {
	dir := t.TempDir()
	copyFixture(t, "Cargo.toml.devtools-feature", filepath.Join(dir, "Cargo.toml"))

	seams, err := (scanner{}).Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	dev := findSeams(seams, "tauri-devtools")
	if len(dev) != 1 {
		t.Fatalf("expected 1 tauri-devtools seam from Cargo, got %d (%+v)", len(dev), seams)
	}
	if dev[0].Confidence != inject.ConfidenceHigh {
		t.Fatalf("expected high confidence, got %s", dev[0].Confidence)
	}
}

// TestScan_SrcTauriSubdir verifies the src-tauri/tauri.conf.json fallback path.
func TestScan_SrcTauriSubdir(t *testing.T) {
	dir := t.TempDir()
	copyFixture(t, "tauri.conf.devtools.json", filepath.Join(dir, "src-tauri", "tauri.conf.json"))
	if !(scanner{}).Detect(dir) {
		t.Fatalf("expected Detect=true for src-tauri/ layout")
	}
	seams, err := (scanner{}).Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(findSeams(seams, "tauri-devtools")) != 1 {
		t.Fatalf("expected 1 tauri-devtools seam for src-tauri layout, got %+v", seams)
	}
}
