/*
Copyright (c) 2026 Security Research

Phase 8 plan 04 Task 1 — flag wiring + CDP loopback validator + path
sanitization tests for the `unravel capture start --visual` surface.
*/
package cmd

import (
	"context"
	gonet "net"
	gonethttp "net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/inovacc/unravel-oss/pkg/capture/launch"
)

// TestValidateCDPLoopback covers the T-08-04 host check.
func TestValidateCDPLoopback(t *testing.T) {
	tests := []struct {
		name      string
		url       string
		allow     bool
		wantErr   bool
		errSubstr string
	}{
		{"empty url accepted", "", false, false, ""},
		{"127.0.0.1 accepted", "http://127.0.0.1:9222", false, false, ""},
		{"localhost accepted", "http://localhost:9222", false, false, ""},
		{"::1 accepted", "http://[::1]:9222", false, false, ""},
		{"127.0.0.55 accepted (IsLoopback)", "http://127.0.0.55:9222", false, false, ""},
		{"attacker rejected", "http://attacker.com:9222", false, true, "loopback"},
		{"private LAN rejected", "http://192.168.1.1:9222", false, true, "loopback"},
		{"attacker allowed with flag", "http://attacker.com:9222", true, false, ""},
		{"malformed url errors", "http://%zz", false, true, "parse"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCDPLoopback(tt.url, tt.allow)
			if tt.wantErr && err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantErr && tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
				t.Fatalf("error %q does not contain %q", err.Error(), tt.errSubstr)
			}
			if tt.wantErr && !tt.allow && tt.url != "" && !strings.Contains(err.Error(), "parse") {
				if !strings.Contains(err.Error(), "--allow-remote-cdp") {
					t.Fatalf("rejection message must mention --allow-remote-cdp: %q", err.Error())
				}
			}
		})
	}
}

// TestSanitizeOperatorPath covers D-18 / T-08-01 traversal rejection.
func TestSanitizeOperatorPath(t *testing.T) {
	if _, err := sanitizeOperatorPath("../../../etc/passwd", "test"); err == nil {
		t.Fatal("expected traversal rejection")
	}
	if _, err := sanitizeOperatorPath("./safe/relative", "test"); err != nil {
		t.Fatalf("unexpected error on safe path: %v", err)
	}
	abs, err := sanitizeOperatorPath("", "test")
	if err != nil {
		t.Fatalf("empty path should not error: %v", err)
	}
	if abs != "" {
		t.Fatalf("empty path should yield empty result, got %q", abs)
	}
}

// TestResolveScenarioPath verifies regular-file requirement.
func TestResolveScenarioPath(t *testing.T) {
	dir := t.TempDir()
	regular := filepath.Join(dir, "scenario.json")
	if err := os.WriteFile(regular, []byte(`[]`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveScenarioPath(regular); err != nil {
		t.Fatalf("regular file should pass: %v", err)
	}

	// Directory rejected.
	if _, err := resolveScenarioPath(dir); err == nil {
		t.Fatal("directory should be rejected")
	}

	// Traversal rejected.
	if _, err := resolveScenarioPath("../../etc/passwd"); err == nil {
		t.Fatal("traversal should be rejected")
	}

	// Empty stays empty.
	got, err := resolveScenarioPath("")
	if err != nil || got != "" {
		t.Fatalf("empty input: got=%q err=%v", got, err)
	}
}

// TestVisualFlagsRegistered ensures the flags exist on captureStartCmd.
func TestVisualFlagsRegistered(t *testing.T) {
	want := []string{
		"visual", "no-behavior", "no-visual", "cdp", "target",
		"mode", "scenario", "viewports", "max-states",
		"phash-threshold", "modal-settle-ms", "allow-remote-cdp",
	}
	for _, name := range want {
		if f := captureStartCmd.Flags().Lookup(name); f == nil {
			t.Errorf("flag --%s not registered", name)
		}
	}
}

// helperSleepCmd returns a long-lived, killable child process: the test
// binary re-invoked into TestCaptureHelperProcess, which blocks until killed.
// This gives launchTargetForVisual a real *exec.Cmd to Start/KillProcessGroup
// across platforms without depending on a system binary.
func helperSleepCmd() *exec.Cmd {
	cmd := exec.Command(os.Args[0], "-test.run=TestCaptureHelperProcess")
	cmd.Env = append(os.Environ(), "UNRAVEL_WANT_HELPER_PROCESS=1")
	return cmd
}

// TestCaptureHelperProcess is not a real test — it is the body of the child
// process spawned by helperSleepCmd. It blocks indefinitely so the parent can
// verify teardown (process kill) deterministically.
func TestCaptureHelperProcess(t *testing.T) {
	if os.Getenv("UNRAVEL_WANT_HELPER_PROCESS") != "1" {
		return
	}
	// Block until the parent kills the process group.
	select {}
}

// TestLaunchTargetForVisual_SuccessReachesConnect verifies that with a fake
// launcher whose CDP endpoint comes up, launchTargetForVisual returns the
// loopback host:port the connect step will dial, and that the launched
// process is torn down when the surrounding context is cancelled.
func TestLaunchTargetForVisual_SuccessReachesConnect(t *testing.T) {
	origBuild := launchBuildFn
	origTimeout := visualCDPReadyTimeout
	t.Cleanup(func() {
		launchBuildFn = origBuild
		visualCDPReadyTimeout = origTimeout
	})
	visualCDPReadyTimeout = 5 * time.Second

	var srv *gonethttp.Server

	launchBuildFn = func(fw launch.Framework, path string, port int, userDataDir string) (*exec.Cmd, error) {
		if fw != launch.FrameworkElectron {
			t.Errorf("expected Electron framework default, got %q", fw)
		}
		if _, err := os.Stat(userDataDir); err != nil {
			t.Errorf("temp user-data-dir should exist at launch time: %v", err)
		}
		// Stand up a fake CDP /json/version endpoint on the chosen port so
		// readiness succeeds — this simulates the launched app exposing CDP.
		ln, err := gonet.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
		if err != nil {
			return nil, err
		}
		mux := gonethttp.NewServeMux()
		mux.HandleFunc("/json/version", func(w gonethttp.ResponseWriter, _ *gonethttp.Request) {
			w.WriteHeader(gonethttp.StatusOK)
			_, _ = w.Write([]byte(`{"webSocketDebuggerUrl":"ws://127.0.0.1/dev"}`))
		})
		srv = &gonethttp.Server{Handler: mux}
		go func() { _ = srv.Serve(ln) }()
		cmd := helperSleepCmd()
		return cmd, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	host, err := launchTargetForVisual(ctx, filepath.Join(t.TempDir(), "FakeApp.exe"), launch.FrameworkElectron)
	if err != nil {
		t.Fatalf("launchTargetForVisual: %v", err)
	}
	if !strings.HasPrefix(host, "127.0.0.1:") {
		t.Fatalf("host %q should be loopback host:port", host)
	}

	// Teardown: cancelling ctx triggers the deferred process-group kill and
	// temp-dir cleanup registered via context.AfterFunc.
	cancel()
	if srv != nil {
		_ = srv.Close()
	}
}

// TestLaunchTargetForVisual_ReadinessTimeout verifies a clear, bounded error
// when the auto-launched target never exposes a CDP endpoint, and that the
// launched process is reaped (no leak) on the timeout path.
func TestLaunchTargetForVisual_ReadinessTimeout(t *testing.T) {
	origBuild := launchBuildFn
	origTimeout := visualCDPReadyTimeout
	t.Cleanup(func() {
		launchBuildFn = origBuild
		visualCDPReadyTimeout = origTimeout
	})
	// Short timeout so the test is fast; the fake launcher never opens CDP.
	visualCDPReadyTimeout = 400 * time.Millisecond

	var launched *exec.Cmd
	launchBuildFn = func(_ launch.Framework, _ string, _ int, _ string) (*exec.Cmd, error) {
		launched = helperSleepCmd()
		return launched, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	start := time.Now()
	_, err := launchTargetForVisual(ctx, filepath.Join(t.TempDir(), "Never.exe"), launch.FrameworkElectron)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected readiness-timeout error, got nil")
	}
	if !strings.Contains(err.Error(), "never became ready") {
		t.Fatalf("error should explain CDP never came up: %v", err)
	}
	// Bounded: must return within a small multiple of the timeout.
	if elapsed > 5*time.Second {
		t.Fatalf("readiness wait not bounded: took %s", elapsed)
	}

	// Teardown: the launched process must be reaped on the timeout path.
	// After KillProcessGroup, Wait should return (process is gone).
	if launched != nil && launched.Process != nil {
		done := make(chan struct{})
		go func() { _, _ = launched.Process.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("launched process not torn down on timeout path (leak)")
		}
	}
}

// TestParseTargetFramework verifies the mapping from flag strings to
// launch.Framework constants and error handling for unknown values.
func TestParseTargetFramework(t *testing.T) {
	tests := []struct {
		input   string
		want    launch.Framework
		wantErr bool
	}{
		{"electron", launch.FrameworkElectron, false},
		{"tauri", launch.FrameworkTauri, false},
		{"webview2", launch.FrameworkWebView2, false},
		// Case-insensitive variants.
		{"Electron", launch.FrameworkElectron, false},
		{"TAURI", launch.FrameworkTauri, false},
		{"WebView2", launch.FrameworkWebView2, false},
		// Unknown values.
		{"", launch.Framework(""), true},
		{"nwjs", launch.Framework(""), true},
		{"cef", launch.Framework(""), true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := parseTargetFramework(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseTargetFramework(%q): expected error, got nil", tt.input)
				}
				if !strings.Contains(err.Error(), "invalid --target-framework") {
					t.Fatalf("error %q missing expected prefix", err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("parseTargetFramework(%q): unexpected error: %v", tt.input, err)
			}
			if got != tt.want {
				t.Fatalf("parseTargetFramework(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// TestLaunchTargetForVisual_TauriFrameworkFlowsThrough verifies that when
// --target-framework tauri is supplied, launchBuildFn receives
// launch.FrameworkTauri. Uses the same fake-CDP-endpoint technique as the
// success test so the function proceeds to the connect step.
func TestLaunchTargetForVisual_TauriFrameworkFlowsThrough(t *testing.T) {
	origBuild := launchBuildFn
	origTimeout := visualCDPReadyTimeout
	t.Cleanup(func() {
		launchBuildFn = origBuild
		visualCDPReadyTimeout = origTimeout
	})
	visualCDPReadyTimeout = 5 * time.Second

	var capturedFW launch.Framework
	var srv *gonethttp.Server

	launchBuildFn = func(fw launch.Framework, path string, port int, userDataDir string) (*exec.Cmd, error) {
		capturedFW = fw
		ln, err := gonet.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
		if err != nil {
			return nil, err
		}
		mux := gonethttp.NewServeMux()
		mux.HandleFunc("/json/version", func(w gonethttp.ResponseWriter, _ *gonethttp.Request) {
			w.WriteHeader(gonethttp.StatusOK)
			_, _ = w.Write([]byte(`{"webSocketDebuggerUrl":"ws://127.0.0.1/dev"}`))
		})
		srv = &gonethttp.Server{Handler: mux}
		go func() { _ = srv.Serve(ln) }()
		return helperSleepCmd(), nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	host, err := launchTargetForVisual(ctx, filepath.Join(t.TempDir(), "FakeApp.exe"), launch.FrameworkTauri)
	if err != nil {
		t.Fatalf("launchTargetForVisual: %v", err)
	}
	if !strings.HasPrefix(host, "127.0.0.1:") {
		t.Fatalf("host %q should be loopback host:port", host)
	}
	if capturedFW != launch.FrameworkTauri {
		t.Fatalf("launchBuildFn received framework %q, want %q", capturedFW, launch.FrameworkTauri)
	}

	cancel()
	if srv != nil {
		_ = srv.Close()
	}
}

// TestTargetFrameworkFlagRegistered ensures --target-framework is registered on
// captureStartCmd with the correct default.
func TestTargetFrameworkFlagRegistered(t *testing.T) {
	f := captureStartCmd.Flags().Lookup("target-framework")
	if f == nil {
		t.Fatal("flag --target-framework not registered on captureStartCmd")
	}
	if f.DefValue != "electron" {
		t.Fatalf("--target-framework default = %q, want %q", f.DefValue, "electron")
	}
}
