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

func TestDetectRuntime_Fixed(t *testing.T) {
	appDir := t.TempDir()
	sub := filepath.Join(appDir, "runtimes", "msedge")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(sub, "msedgewebview2.exe")
	if err := os.WriteFile(exe, []byte{0}, 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := DetectRuntime(appDir)
	if err != nil {
		t.Fatalf("DetectRuntime: %v", err)
	}
	if info.Mode != "fixed" {
		t.Errorf("Mode=%q, want fixed", info.Mode)
	}
	if info.InstallDir != sub {
		t.Errorf("InstallDir=%q, want %q", info.InstallDir, sub)
	}
}

func TestDetectRuntime_Unknown(t *testing.T) {
	if runtime.GOOS == "windows" {
		// On Windows the registry may report an evergreen runtime; that is
		// a legitimate outcome for this environment.
		t.Skip("evergreen registry may be present on Windows")
	}
	info, err := DetectRuntime(t.TempDir())
	if err != nil {
		t.Fatalf("DetectRuntime: %v", err)
	}
	if info.Mode != "unknown" {
		t.Errorf("Mode=%q, want unknown", info.Mode)
	}
}

func TestDetectRuntime_EmptyAppDir(t *testing.T) {
	info, err := DetectRuntime("")
	if err != nil {
		t.Fatalf("DetectRuntime: %v", err)
	}
	// With no app dir we fall through to evergreen-or-unknown; both are OK.
	if info.Mode != "unknown" && info.Mode != "evergreen" {
		t.Errorf("Mode=%q, want unknown or evergreen", info.Mode)
	}
}
