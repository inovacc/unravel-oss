/*
Copyright (c) 2026 Security Research
*/
package frida

import (
	"bytes"
	"context"
	"os/exec"
	"testing"
	"time"
)

func restoreExecCommand(old func(context.Context, string, ...string) *exec.Cmd) {
	execCommand = old
}

func TestNewRunner_Defaults(t *testing.T) {
	r := NewRunner("com.example.app")

	if r.Host != "127.0.0.1:27042" {
		t.Errorf("default host = %q, want %q", r.Host, "127.0.0.1:27042")
	}

	if r.PackageName != "com.example.app" {
		t.Errorf("package = %q, want %q", r.PackageName, "com.example.app")
	}

	if r.DeviceID != "" {
		t.Errorf("device = %q, want empty", r.DeviceID)
	}

	if r.Output == nil {
		t.Error("output should default to os.Stdout")
	}

	if r.Verbose {
		t.Error("verbose should default to false")
	}
}

func TestNewRunner_Options(t *testing.T) {
	var buf bytes.Buffer

	r := NewRunner("com.test.app",
		WithHost("192.168.1.100:27042"),
		WithDevice("emulator-5554"),
		WithVerbose(true),
		WithOutput(&buf),
	)

	if r.Host != "192.168.1.100:27042" {
		t.Errorf("host = %q, want %q", r.Host, "192.168.1.100:27042")
	}

	if r.DeviceID != "emulator-5554" {
		t.Errorf("device = %q, want %q", r.DeviceID, "emulator-5554")
	}

	if !r.Verbose {
		t.Error("verbose should be true")
	}

	if r.Output != &buf {
		t.Error("output should be the provided buffer")
	}
}

func TestCheckDevice_FridaNotFound(t *testing.T) {
	old := execCommand
	defer restoreExecCommand(old)

	execCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		// Use a command that does not exist
		return exec.CommandContext(ctx, "frida-ps-nonexistent-binary-xyz")
	}

	r := NewRunner("com.example.app")
	err := r.CheckDevice(context.Background())

	if err == nil {
		t.Fatal("expected error when frida-ps not found")
	}
}

func TestCheckDevice_Success(t *testing.T) {
	if _, err := exec.LookPath("frida-ps"); err != nil {
		t.Skip("frida-ps not installed")
	}

	old := execCommand
	defer restoreExecCommand(old)

	execCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "echo", "PID  Name\n---  ----\n123  system_server")
	}

	r := NewRunner("com.example.app")
	err := r.CheckDevice(context.Background())

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCheckDevice_DeviceArgs(t *testing.T) {
	old := execCommand
	defer restoreExecCommand(old)

	var capturedArgs []string

	execCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		capturedArgs = args
		return exec.CommandContext(ctx, "echo", "ok")
	}

	// Test with device ID
	r := NewRunner("com.example.app", WithDevice("emulator-5554"))
	_ = r.CheckDevice(context.Background())

	if len(capturedArgs) < 2 || capturedArgs[0] != "-D" || capturedArgs[1] != "emulator-5554" {
		t.Errorf("device args = %v, want [-D emulator-5554]", capturedArgs)
	}

	// Test with host
	r = NewRunner("com.example.app")
	_ = r.CheckDevice(context.Background())

	if len(capturedArgs) < 2 || capturedArgs[0] != "-H" || capturedArgs[1] != "127.0.0.1:27042" {
		t.Errorf("host args = %v, want [-H 127.0.0.1:27042]", capturedArgs)
	}
}

func TestRunScript_FridaNotFound(t *testing.T) {
	old := execCommand
	defer restoreExecCommand(old)

	execCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "frida-nonexistent-binary-xyz")
	}

	r := NewRunner("com.example.app")
	script := GeneratedScript{
		Name:    "test_script",
		Content: "console.log('hello');",
	}

	_, err := r.RunScript(context.Background(), script, 5*time.Second)

	if err == nil {
		t.Fatal("expected error when frida not found")
	}
}

func TestRunScript_Success(t *testing.T) {
	if _, err := exec.LookPath("frida"); err != nil {
		t.Skip("frida not installed")
	}

	old := execCommand
	defer restoreExecCommand(old)

	execCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "echo", "[HOOK] test output\n[HOOK] second line")
	}

	var buf bytes.Buffer
	r := NewRunner("com.example.app", WithOutput(&buf), WithVerbose(true))

	script := GeneratedScript{
		Name:    "test_hook",
		Content: "console.log('[HOOK] test output');",
	}

	result, err := r.RunScript(context.Background(), script, 5*time.Second)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.ScriptName != "test_hook" {
		t.Errorf("script name = %q, want %q", result.ScriptName, "test_hook")
	}

	if result.Duration == 0 {
		t.Error("duration should be non-zero")
	}

	if result.Started.IsZero() {
		t.Error("started should be set")
	}
}

func TestRunScript_Timeout(t *testing.T) {
	old := execCommand
	defer restoreExecCommand(old)

	execCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		// sleep for longer than timeout
		return exec.CommandContext(ctx, "sleep", "10")
	}

	r := NewRunner("com.example.app")
	script := GeneratedScript{
		Name:    "slow_script",
		Content: "console.log('slow');",
	}

	ctx := context.Background()
	_, err := r.RunScript(ctx, script, 100*time.Millisecond)

	if err == nil {
		t.Fatal("expected timeout error")
	}
}

func TestSpawn_FridaNotFound(t *testing.T) {
	old := execCommand
	defer restoreExecCommand(old)

	execCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "frida-nonexistent-binary-xyz")
	}

	r := NewRunner("com.example.app")
	script := GeneratedScript{
		Name:    "test_spawn",
		Content: "console.log('spawn');",
	}

	_, err := r.Spawn(context.Background(), script, 5*time.Second)

	if err == nil {
		t.Fatal("expected error when frida not found")
	}
}

func TestSpawn_Success(t *testing.T) {
	if _, err := exec.LookPath("frida"); err != nil {
		t.Skip("frida not installed")
	}

	old := execCommand
	defer restoreExecCommand(old)

	var capturedArgs []string

	execCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		capturedArgs = args
		return exec.CommandContext(ctx, "echo", "[HOOK] spawned")
	}

	r := NewRunner("com.example.app")
	script := GeneratedScript{
		Name:    "test_spawn",
		Content: "console.log('spawned');",
	}

	_, err := r.Spawn(context.Background(), script, 5*time.Second)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Check that -f flag was used (spawn mode)
	foundF := false
	for i, arg := range capturedArgs {
		if arg == "-f" && i+1 < len(capturedArgs) && capturedArgs[i+1] == "com.example.app" {
			foundF = true
			break
		}
	}

	if !foundF {
		t.Errorf("spawn should use -f flag, got args: %v", capturedArgs)
	}
}

func TestRunAll_Empty(t *testing.T) {
	r := NewRunner("com.example.app")
	result, err := r.RunAll(context.Background(), nil, 5*time.Second)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.PackageName != "com.example.app" {
		t.Errorf("package = %q, want %q", result.PackageName, "com.example.app")
	}

	if len(result.Scripts) != 0 {
		t.Errorf("scripts count = %d, want 0", len(result.Scripts))
	}

	// Duration may be zero when no scripts run (sub-microsecond execution)
	_ = result.Duration
}

func TestRunAll_CollectsResults(t *testing.T) {
	old := execCommand
	defer restoreExecCommand(old)

	execCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "echo", "[HOOK] output line")
	}

	r := NewRunner("com.example.app")

	scripts := []GeneratedScript{
		{Name: "script_a", Content: "console.log('a');"},
		{Name: "script_b", Content: "console.log('b');"},
		{Name: "script_c", Content: "console.log('c');"},
	}

	result, err := r.RunAll(context.Background(), scripts, 5*time.Second)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Scripts) != 3 {
		t.Fatalf("scripts count = %d, want 3", len(result.Scripts))
	}

	for i, s := range result.Scripts {
		if s.ScriptName != scripts[i].Name {
			t.Errorf("script[%d] name = %q, want %q", i, s.ScriptName, scripts[i].Name)
		}
	}
}

func TestRunAll_DeviceInResult(t *testing.T) {
	old := execCommand
	defer restoreExecCommand(old)

	execCommand = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		return exec.CommandContext(ctx, "echo", "ok")
	}

	// With device ID
	r := NewRunner("com.example.app", WithDevice("emulator-5554"))
	result, _ := r.RunAll(context.Background(), nil, 5*time.Second)

	if result.Device != "emulator-5554" {
		t.Errorf("device = %q, want %q", result.Device, "emulator-5554")
	}

	// With host (no device ID)
	r = NewRunner("com.example.app")
	result, _ = r.RunAll(context.Background(), nil, 5*time.Second)

	if result.Device != "127.0.0.1:27042" {
		t.Errorf("device = %q, want %q", result.Device, "127.0.0.1:27042")
	}
}

func TestIsNotFound(t *testing.T) {
	err := exec.ErrNotFound
	if !isNotFound(err) {
		t.Error("should detect ErrNotFound")
	}
}
