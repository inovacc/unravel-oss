/*
Copyright (c) 2026 Security Research
*/

package analyze

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func mkProfile(t *testing.T, root, name string) string {
	t.Helper()
	p := filepath.Join(root, name)
	if err := os.MkdirAll(p, 0o700); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAnalyzeUDF_Empty(t *testing.T) {
	eb := t.TempDir()
	mkProfile(t, eb, "Default")
	res, err := Analyze(eb, DefaultOptions())
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(res.Profiles) != 1 || res.Profiles[0].Name != "Default" {
		t.Errorf("profiles=%+v", res.Profiles)
	}
	if len(res.ProfileData) != 1 {
		t.Fatalf("ProfileData len=%d", len(res.ProfileData))
	}
	// No subfolders → no per-step errors (everything is "not found", soft).
	if len(res.ProfileData[0].Errors) != 0 {
		t.Errorf("unexpected errors: %+v", res.ProfileData[0].Errors)
	}
}

func TestAnalyzeUDF_WithFixtures(t *testing.T) {
	eb := t.TempDir()
	defaultDir := mkProfile(t, eb, "Default")
	// Empty LevelDB dir — parser returns empty result without error.
	if err := os.MkdirAll(filepath.Join(defaultDir, "Local Storage", "leveldb"), 0o700); err != nil {
		t.Fatal(err)
	}
	// Write a valid Preferences file.
	prefs := filepath.Join(defaultDir, "Preferences")
	if err := os.WriteFile(prefs, []byte(`{"profile":{"name":"Fixture"}}`), 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := Analyze(eb, DefaultOptions())
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(res.ProfileData) != 1 {
		t.Fatalf("ProfileData len=%d", len(res.ProfileData))
	}
	pb := res.ProfileData[0]
	if pb.LocalStorage == nil {
		t.Error("LocalStorage nil — leveldb extractor not invoked")
	}
	if pb.Preferences == nil {
		t.Error("Preferences nil — ParsePreferences not invoked")
	}
	if len(pb.Errors) != 0 {
		t.Errorf("unexpected per-profile errors: %+v", pb.Errors)
	}
}

func TestAnalyzeUDF_SymlinkRejected(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires elevation on Windows")
	}
	eb := t.TempDir()
	// Make the Default profile dir a symlink to another tempdir.
	target := t.TempDir()
	if err := os.Symlink(target, filepath.Join(eb, "Default")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	res, err := Analyze(eb, DefaultOptions())
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(res.ProfileData) != 1 {
		t.Fatalf("ProfileData len=%d", len(res.ProfileData))
	}
	found := false
	for _, e := range res.ProfileData[0].Errors {
		if contains(e, "symlink rejected") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected 'symlink rejected' warning, got %+v", res.ProfileData[0].Errors)
	}
}

func TestAnalyzeUDF_NotExist(t *testing.T) {
	res, err := Analyze(filepath.Join(t.TempDir(), "missing"), DefaultOptions())
	if err != nil {
		t.Fatalf("Analyze: %v (want nil)", err)
	}
	if len(res.Profiles) != 0 {
		t.Errorf("profiles=%+v", res.Profiles)
	}
}

func contains(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestResult_HasRecoveredCSSField(t *testing.T) {
	var r UDFResult
	r.RecoveredCSS = append(r.RecoveredCSS, RecoveredCSSEntry{Path: "p", Source: ".a{}"})
	if len(r.RecoveredCSS) != 1 {
		t.Fatal("RecoveredCSS not wired on analyze result")
	}
}
