/*
Copyright (c) 2026 Security Research
*/

package udf

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEnumerateProfiles(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"Default", "Profile 1", "Profile 2", "Guest Profile", "System Profile", "NotAProfile", "Profile abc"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	got, err := EnumerateProfiles(root)
	if err != nil {
		t.Fatalf("EnumerateProfiles: %v", err)
	}
	if len(got) != 5 {
		t.Fatalf("got %d profiles, want 5: %+v", len(got), got)
	}
	want := []string{"Default", "Profile 1", "Profile 2", "Guest Profile", "System Profile"}
	for i, p := range got {
		if p.Name != want[i] {
			t.Errorf("profile[%d]: got %q, want %q", i, p.Name, want[i])
		}
		if p.Path != filepath.Join(root, p.Name) {
			t.Errorf("profile[%d].Path=%q", i, p.Path)
		}
	}
}

func TestEnumerateProfiles_OnlyDefault(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "Default"), 0o700); err != nil {
		t.Fatal(err)
	}
	got, err := EnumerateProfiles(root)
	if err != nil {
		t.Fatalf("EnumerateProfiles: %v", err)
	}
	if len(got) != 1 || got[0].Name != "Default" {
		t.Errorf("got %+v, want [Default]", got)
	}
}

func TestEnumerateProfiles_Empty(t *testing.T) {
	root := t.TempDir()
	got, err := EnumerateProfiles(root)
	if err != nil {
		t.Fatalf("EnumerateProfiles: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %+v, want empty", got)
	}
}

func TestEnumerateProfiles_NotExist(t *testing.T) {
	got, err := EnumerateProfiles(filepath.Join(t.TempDir(), "does-not-exist"))
	if err != nil {
		t.Fatalf("EnumerateProfiles: %v (want nil for ENOENT)", err)
	}
	if len(got) != 0 {
		t.Errorf("got %+v, want empty", got)
	}
}

func TestEnumerateProfiles_FileNotDir(t *testing.T) {
	root := t.TempDir()
	// "Default" as a file, not a directory
	if err := os.WriteFile(filepath.Join(root, "Default"), []byte{0}, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := EnumerateProfiles(root)
	if err != nil {
		t.Fatalf("EnumerateProfiles: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %+v, want empty (file skipped)", got)
	}
}

func TestIsProfileDirName(t *testing.T) {
	cases := map[string]bool{
		"Default":        true,
		"Guest Profile":  true,
		"System Profile": true,
		"Profile 1":      true,
		"Profile 42":     true,
		"Profile 0":      false,
		"Profile -1":     false,
		"Profile abc":    false,
		"Profile":        false,
		"profile 1":      false, // case-sensitive per Chromium
		"random":         false,
	}
	for n, want := range cases {
		if got := isProfileDirName(n); got != want {
			t.Errorf("isProfileDirName(%q)=%v want %v", n, got, want)
		}
	}
}
