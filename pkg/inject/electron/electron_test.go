/*
Copyright (c) 2026 Security Research
*/
package electron

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/inject"
)

// fixtureDir copies a single main.js fixture into a temp app layout
// (resources/app/main.js) and returns the appDir.
func fixtureDir(t *testing.T, fixtureBasename string) string {
	t.Helper()
	src := filepath.Join("testdata", fixtureBasename)
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read fixture %s: %v", src, err)
	}
	app := t.TempDir()
	dst := filepath.Join(app, "resources", "app")
	if err := os.MkdirAll(dst, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dst, "main.js"), data, 0o644); err != nil {
		t.Fatalf("write main.js: %v", err)
	}
	return app
}

func countSeams(seams []inject.Seam, kind string) int {
	n := 0
	for _, s := range seams {
		if s.Kind == kind {
			n++
		}
	}
	return n
}

func findSeam(seams []inject.Seam, kind string) *inject.Seam {
	for i := range seams {
		if seams[i].Kind == kind {
			return &seams[i]
		}
	}
	return nil
}

// --- Detect tests ---

func TestDetect_ASARPresent(t *testing.T) {
	app := t.TempDir()
	resDir := filepath.Join(app, "resources")
	if err := os.MkdirAll(resDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	// Empty file is fine — Detect only stats it.
	if err := os.WriteFile(filepath.Join(resDir, "app.asar"), []byte("x"), 0o644); err != nil {
		t.Fatalf("write asar: %v", err)
	}
	if !(scanner{}).Detect(app) {
		t.Fatalf("expected Detect=true when resources/app.asar present")
	}
}

func TestDetect_PackageJSONElectronDep(t *testing.T) {
	app := t.TempDir()
	pkg := `{"name":"x","dependencies":{"electron":"^28.0.0"}}`
	if err := os.WriteFile(filepath.Join(app, "package.json"), []byte(pkg), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}
	if !(scanner{}).Detect(app) {
		t.Fatalf("expected Detect=true when package.json declares electron dep")
	}
}

func TestDetect_NoSignals(t *testing.T) {
	app := t.TempDir()
	if (scanner{}).Detect(app) {
		t.Fatalf("expected Detect=false on empty dir")
	}
}

// --- Scan tests ---

func TestScan_ExplicitNodeIntegration(t *testing.T) {
	app := fixtureDir(t, "main_explicit_node_integration.js")
	seams, err := (scanner{}).Scan(context.Background(), app)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	// Expected seams (high confidence):
	//   nodeIntegration, contextIsolation, sandbox, preload-script,
	//   command-line-switch:remote-debugging, executejavascript-call.
	wantHigh := []string{
		"browser-window-pref:nodeIntegration",
		"browser-window-pref:contextIsolation",
		"browser-window-pref:sandbox",
		"command-line-switch:remote-debugging",
		"executejavascript-call",
	}
	for _, k := range wantHigh {
		s := findSeam(seams, k)
		if s == nil {
			t.Errorf("missing seam %s; got %+v", k, seams)
			continue
		}
		if s.Confidence != inject.ConfidenceHigh {
			t.Errorf("seam %s: want high confidence, got %s", k, s.Confidence)
		}
	}

	// preload-script should be medium (preload.js not present alongside).
	if s := findSeam(seams, "preload-script"); s == nil {
		t.Errorf("missing preload-script seam")
	} else if s.Confidence != inject.ConfidenceMedium {
		t.Errorf("preload-script: want medium when file absent, got %s", s.Confidence)
	}
}

func TestScan_ImplicitDefaults(t *testing.T) {
	app := fixtureDir(t, "main_implicit_defaults.js")
	seams, err := (scanner{}).Scan(context.Background(), app)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	// BrowserWindow constructor present, no webPreferences → 3 framework-default
	// inference seams at low confidence.
	for _, k := range []string{
		"browser-window-pref:nodeIntegration",
		"browser-window-pref:contextIsolation",
		"browser-window-pref:sandbox",
	} {
		s := findSeam(seams, k)
		if s == nil {
			t.Errorf("missing default-inference seam %s", k)
			continue
		}
		if s.Confidence != inject.ConfidenceLow {
			t.Errorf("seam %s: want low (framework-default), got %s", k, s.Confidence)
		}
	}
	// No preload, executeJS, or remote-debugging in implicit fixture.
	for _, k := range []string{"preload-script", "executejavascript-call", "command-line-switch:remote-debugging"} {
		if findSeam(seams, k) != nil {
			t.Errorf("unexpected seam %s in implicit-defaults case", k)
		}
	}
}

func TestScan_Obfuscated(t *testing.T) {
	app := fixtureDir(t, "main_obfuscated.js")
	seams, err := (scanner{}).Scan(context.Background(), app)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	// All webPreferences hits should be MEDIUM (demoted by obfuscation heuristic).
	for _, k := range []string{
		"browser-window-pref:nodeIntegration",
		"browser-window-pref:contextIsolation",
		"browser-window-pref:sandbox",
	} {
		s := findSeam(seams, k)
		if s == nil {
			t.Errorf("missing seam %s in obfuscated bundle", k)
			continue
		}
		if s.Confidence != inject.ConfidenceMedium {
			t.Errorf("obfuscated seam %s: want medium, got %s", k, s.Confidence)
		}
	}
	// executeJS should be present at medium too.
	if s := findSeam(seams, "executejavascript-call"); s == nil {
		t.Errorf("missing executejavascript-call seam")
	} else if s.Confidence != inject.ConfidenceMedium {
		t.Errorf("executejavascript-call: want medium in obfuscated bundle, got %s", s.Confidence)
	}
}

func TestScan_PreloadFileExistsBumpsConfidence(t *testing.T) {
	// Case A: preload.js present alongside main.js → high.
	app := fixtureDir(t, "main_explicit_node_integration.js")
	preload := filepath.Join(app, "resources", "app", "preload.js")
	if err := os.WriteFile(preload, []byte("// preload"), 0o644); err != nil {
		t.Fatalf("write preload: %v", err)
	}
	seams, err := (scanner{}).Scan(context.Background(), app)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	s := findSeam(seams, "preload-script")
	if s == nil {
		t.Fatalf("missing preload-script seam")
	}
	if s.Confidence != inject.ConfidenceHigh {
		t.Errorf("preload present: want high, got %s", s.Confidence)
	}

	// Case B: preload absent → medium.
	app2 := fixtureDir(t, "main_explicit_node_integration.js")
	seams2, err := (scanner{}).Scan(context.Background(), app2)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	s2 := findSeam(seams2, "preload-script")
	if s2 == nil {
		t.Fatalf("missing preload-script seam (absent case)")
	}
	if s2.Confidence != inject.ConfidenceMedium {
		t.Errorf("preload absent: want medium, got %s", s2.Confidence)
	}
}

// TestScan_ASARWalk verifies the ASAR loader path: place the fixture asar
// at resources/app.asar and assert seams are emitted from the embedded main.js.
func TestScan_ASARWalk(t *testing.T) {
	app := t.TempDir()
	res := filepath.Join(app, "resources")
	if err := os.MkdirAll(res, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	asarSrc, err := os.ReadFile(filepath.Join("testdata", "preload-fixture.asar"))
	if err != nil {
		t.Fatalf("read asar fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(res, "app.asar"), asarSrc, 0o644); err != nil {
		t.Fatalf("write asar: %v", err)
	}

	if !(scanner{}).Detect(app) {
		t.Fatalf("Detect should find ASAR")
	}
	seams, err := (scanner{}).Scan(context.Background(), app)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	// Embedded main.js has explicit literal webPreferences → expect high seams.
	if n := countSeams(seams, "browser-window-pref:nodeIntegration"); n != 1 {
		t.Errorf("want 1 nodeIntegration seam from ASAR, got %d (seams=%+v)", n, seams)
	}
	if s := findSeam(seams, "preload-script"); s == nil {
		t.Errorf("missing preload-script seam from ASAR")
	}
}
