/*
Copyright (c) 2026 Security Research

06-04 Task 3 (D-14): tests for the recovered_<bundler> name_quality
extension. Validates the enum values exist and that
NameQualityForBundleDir maps a manifest.json bundle_kind to the
correct NameQuality.
*/
package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNameQuality_RecoveredEnumValues(t *testing.T) {
	cases := map[NameQuality]string{
		NameQualityRecoveredWebpack: "recovered_webpack",
		NameQualityRecoveredVite:    "recovered_vite",
		NameQualityRecoveredEsbuild: "recovered_esbuild",
		NameQualityRecoveredRollup:  "recovered_rollup",
	}
	for got, want := range cases {
		if string(got) != want {
			t.Errorf("NameQuality const = %q; want %q", got, want)
		}
	}
}

func TestNameQualityForBundleDir_Webpack(t *testing.T) {
	dir := t.TempDir()
	manifest := []byte(`{"bundle_kind":"webpack","modules_count":42}`)
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), manifest, 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	got := NameQualityForBundleDir(dir)
	if got != NameQualityRecoveredWebpack {
		t.Errorf("NameQualityForBundleDir = %q; want %q", got, NameQualityRecoveredWebpack)
	}
}

func TestNameQualityForBundleDir_AllKinds(t *testing.T) {
	cases := map[string]NameQuality{
		"webpack": NameQualityRecoveredWebpack,
		"vite":    NameQualityRecoveredVite,
		"esbuild": NameQualityRecoveredEsbuild,
		"rollup":  NameQualityRecoveredRollup,
		"unknown": NameQualityRaw,
	}
	for kind, want := range cases {
		dir := t.TempDir()
		manifest := []byte(`{"bundle_kind":"` + kind + `"}`)
		if err := os.WriteFile(filepath.Join(dir, "manifest.json"), manifest, 0o644); err != nil {
			t.Fatalf("write manifest: %v", err)
		}
		got := NameQualityForBundleDir(dir)
		if got != want {
			t.Errorf("kind=%q: got %q; want %q", kind, got, want)
		}
	}
}

func TestNameQualityForBundleDir_NoManifest_DefaultsRaw(t *testing.T) {
	dir := t.TempDir()
	got := NameQualityForBundleDir(dir)
	if got != NameQualityRaw {
		t.Errorf("missing manifest: got %q; want %q", got, NameQualityRaw)
	}
}

func TestScanRecoveredBundleDir_TagsModulesWithKind(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"),
		[]byte(`{"bundle_kind":"webpack"}`), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	mods := filepath.Join(dir, "modules")
	if err := os.MkdirAll(mods, 0o755); err != nil {
		t.Fatalf("mkdir mods: %v", err)
	}
	if err := os.WriteFile(filepath.Join(mods, "Auth.js"),
		[]byte("export const Auth = {};"), 0o644); err != nil {
		t.Fatalf("write Auth.js: %v", err)
	}
	if err := os.WriteFile(filepath.Join(mods, "User.js"),
		[]byte("export class User {}"), 0o644); err != nil {
		t.Fatalf("write User.js: %v", err)
	}

	out, err := ScanRecoveredBundleDir(dir)
	if err != nil {
		t.Fatalf("ScanRecoveredBundleDir: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("modules count = %d; want 2", len(out))
	}
	for _, m := range out {
		if m.NameQuality != NameQualityRecoveredWebpack {
			t.Errorf("module %q: NameQuality=%q; want %q",
				m.Name, m.NameQuality, NameQualityRecoveredWebpack)
		}
	}
}
