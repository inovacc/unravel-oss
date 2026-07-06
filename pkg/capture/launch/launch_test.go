/*
Copyright (c) 2026 Security Research
*/
package launch

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// makeFakeBinary writes a 0-byte regular file in t.TempDir() and returns its
// absolute path. Adequate for command-assembly tests (we never spawn).
func makeFakeBinary(t *testing.T, name string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte{}, 0o755); err != nil {
		t.Fatalf("write fake binary: %v", err)
	}
	return p
}

func TestLaunchElectronArgs(t *testing.T) {
	bin := makeFakeBinary(t, "fakeapp")
	udd := t.TempDir()
	cmd, err := LaunchElectron(bin, 9222, udd)
	if err != nil {
		t.Fatalf("LaunchElectron: %v", err)
	}
	if cmd.Path == "" {
		t.Fatal("empty cmd.Path")
	}
	args := strings.Join(cmd.Args, " ")
	if !strings.Contains(args, "--remote-debugging-port=9222") {
		t.Errorf("missing --remote-debugging-port=9222 in args: %v", cmd.Args)
	}
	if !strings.Contains(args, "--user-data-dir="+udd) {
		t.Errorf("missing --user-data-dir=%s in args: %v", udd, cmd.Args)
	}
}

func TestLaunchTauriEnv(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Tauri auto-launch requires Windows host")
	}
	bin := makeFakeBinary(t, "fakeapp.exe")
	udd := t.TempDir()
	cmd, err := LaunchTauri(bin, 9222, udd)
	if err != nil {
		t.Fatalf("LaunchTauri: %v", err)
	}
	envJoined := strings.Join(cmd.Env, "\n")
	if !strings.Contains(envJoined, "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS=--remote-debugging-port=9222 --user-data-dir="+udd) {
		t.Errorf("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS missing or wrong; env=%s", envJoined)
	}
	if !strings.Contains(envJoined, "WEBVIEW2_USER_DATA_FOLDER="+udd) {
		t.Errorf("WEBVIEW2_USER_DATA_FOLDER missing; env=%s", envJoined)
	}
}

func TestLaunchTauriRefusesNonWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("non-Windows-only test")
	}
	bin := makeFakeBinary(t, "fakeapp")
	_, err := LaunchTauri(bin, 9222, t.TempDir())
	if err == nil {
		t.Fatal("expected error on non-Windows")
	}
	if !strings.Contains(err.Error(), "WKWebView/webkit2gtk does not support CDP") {
		t.Errorf("expected WKWebView message in err, got %v", err)
	}
}

func TestLaunchWebView2Env(t *testing.T) {
	bin := makeFakeBinary(t, "wv2app.exe")
	udd := t.TempDir()
	cmd, err := LaunchWebView2(bin, 9333, udd)
	if err != nil {
		t.Fatalf("LaunchWebView2: %v", err)
	}
	envJoined := strings.Join(cmd.Env, "\n")
	if !strings.Contains(envJoined, "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS=--remote-debugging-port=9333") {
		t.Errorf("missing WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS; env=%s", envJoined)
	}
	if !strings.Contains(envJoined, "WEBVIEW2_USER_DATA_FOLDER="+udd) {
		t.Errorf("missing WEBVIEW2_USER_DATA_FOLDER; env=%s", envJoined)
	}
}

func TestLaunchValidatesPath(t *testing.T) {
	// Path traversal in input rejected (rule fires before lstat).
	if _, err := LaunchElectron("../../etc/passwd", 9222, t.TempDir()); err == nil {
		t.Fatal("expected error on traversal input")
	} else if !errors.Is(err, ErrPathTraversal) {
		t.Logf("got err: %v (acceptable if lstat-based)", err)
	}

	// Symlink rejection.
	if runtime.GOOS != "windows" {
		// On Windows, creating symlinks needs Developer Mode/admin; skip there.
		realBin := makeFakeBinary(t, "real")
		linkDir := t.TempDir()
		linkPath := filepath.Join(linkDir, "link")
		if err := os.Symlink(realBin, linkPath); err != nil {
			t.Skipf("cannot create symlink: %v", err)
		}
		if _, err := LaunchElectron(linkPath, 9222, t.TempDir()); err == nil || !errors.Is(err, ErrSymlink) {
			t.Errorf("expected ErrSymlink, got %v", err)
		}
	}
}

func TestRegistryDispatch(t *testing.T) {
	bin := makeFakeBinary(t, "app")
	udd := t.TempDir()

	if _, err := Build(FrameworkElectron, bin, 9222, udd); err != nil {
		t.Errorf("Build(electron): %v", err)
	}

	if _, err := Build(Framework("unknown"), bin, 9222, udd); err == nil {
		t.Error("expected error for unknown framework")
	} else if !errors.Is(err, ErrUnsupported) {
		t.Errorf("expected ErrUnsupported, got %v", err)
	}
}
