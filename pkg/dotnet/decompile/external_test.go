/*
Copyright (c) 2026 Security Research
*/
package decompile

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// mockBinDir is the absolute path of the directory containing the compiled
// mock-ilspycmd binary. Populated by TestMain.
var mockBinDir string

func TestMain(m *testing.M) {
	// Build mock-ilspycmd from testdata/mockilspy.
	tmp, err := os.MkdirTemp("", "mockilspy-*")
	if err != nil {
		panic("mockilspy: tempdir: " + err.Error())
	}

	binName := "ilspycmd"
	if runtime.GOOS == "windows" {
		binName += ".exe"
	}

	binPath := filepath.Join(tmp, binName)

	build := exec.Command("go", "build", "-o", binPath, "./testdata/mockilspy")
	build.Stderr = os.Stderr
	build.Stdout = os.Stderr
	if err := build.Run(); err != nil {
		// Skip rather than fail hard — caller should still see real-binary path.
		_, _ = os.Stderr.WriteString("mockilspy build failed: " + err.Error() + "\n")
		os.Exit(m.Run())
	}

	mockBinDir = tmp

	// Prepend tmp to PATH so exec.LookPath finds our mock first.
	origPath := os.Getenv("PATH")
	_ = os.Setenv("PATH", tmp+string(os.PathListSeparator)+origPath)

	code := m.Run()

	_ = os.Setenv("PATH", origPath)
	_ = os.RemoveAll(tmp)

	os.Exit(code)
}

func TestRunILSpyCmd_MissingBinary(t *testing.T) {
	// Empty PATH so LookPath fails.
	t.Setenv("PATH", "")

	_, err := locateILSpy()
	if err == nil {
		t.Fatal("locateILSpy with empty PATH: want error, got nil")
	}

	if !strings.Contains(err.Error(), "ilspycmd not found") {
		t.Errorf("error %q does not contain 'ilspycmd not found'", err.Error())
	}

	if !strings.Contains(err.Error(), "dotnet tool install -g ilspycmd") {
		t.Errorf("error %q missing install hint", err.Error())
	}
}

func TestRunILSpyCmd_OK(t *testing.T) {
	if mockBinDir == "" {
		t.Skip("mock ilspycmd unavailable")
	}
	t.Setenv("MOCK_ILSPYCMD_MODE", "ok")

	bin, err := locateILSpy()
	if err != nil {
		t.Fatalf("locateILSpy: %v", err)
	}

	out := t.TempDir()
	asm := filepath.Join(t.TempDir(), "fake.dll")
	_ = os.WriteFile(asm, []byte("not a real dll"), 0o644)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := runILSpyCmd(ctx, bin, asm, out); err != nil {
		t.Fatalf("runILSpyCmd ok: %v", err)
	}

	mockOut := filepath.Join(out, "MockNs", "Mock.cs")
	if _, err := os.Stat(mockOut); err != nil {
		t.Errorf("expected mock output %s: %v", mockOut, err)
	}
}

func TestRunILSpyCmd_Crash(t *testing.T) {
	if mockBinDir == "" {
		t.Skip("mock ilspycmd unavailable")
	}
	t.Setenv("MOCK_ILSPYCMD_MODE", "crash")

	bin, _ := locateILSpy()
	asm := filepath.Join(t.TempDir(), "fake.dll")
	_ = os.WriteFile(asm, []byte("x"), 0o644)
	out := t.TempDir()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := runILSpyCmd(ctx, bin, asm, out)
	if err == nil {
		t.Fatal("runILSpyCmd crash: want error, got nil")
	}

	if !strings.Contains(err.Error(), "panic: bad metadata") {
		t.Errorf("expected stderr captured in error %q", err.Error())
	}
}

func TestRunILSpyCmd_Timeout(t *testing.T) {
	if mockBinDir == "" {
		t.Skip("mock ilspycmd unavailable")
	}
	t.Setenv("MOCK_ILSPYCMD_MODE", "hang")

	bin, _ := locateILSpy()
	asm := filepath.Join(t.TempDir(), "fake.dll")
	_ = os.WriteFile(asm, []byte("x"), 0o644)
	out := t.TempDir()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	err := runILSpyCmd(ctx, bin, asm, out)
	if err == nil {
		t.Fatal("runILSpyCmd hang: want error, got nil")
	}

	// Either context.DeadlineExceeded wrapped or process-killed signal in stderr.
	if !errors.Is(err, context.DeadlineExceeded) && !strings.Contains(err.Error(), "killed") && !strings.Contains(err.Error(), "signal") {
		t.Errorf("expected deadline/kill error, got %q", err.Error())
	}
}

func TestDetectVersion_Captured(t *testing.T) {
	if mockBinDir == "" {
		t.Skip("mock ilspycmd unavailable")
	}
	t.Setenv("MOCK_ILSPYCMD_MODE", "version")

	bin, err := locateILSpy()
	if err != nil {
		t.Fatalf("locateILSpy: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	v := detectVersion(ctx, bin)
	if v == "" || v == "unknown" {
		t.Errorf("detectVersion = %q, want non-empty / non-unknown", v)
	}

	if !strings.Contains(v, "mock-ilspycmd") {
		t.Errorf("detectVersion = %q, want substring 'mock-ilspycmd'", v)
	}
}
