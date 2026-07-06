/*
Copyright (c) 2026 Security Research
*/

package capture_test

import (
	"context"
	"errors"
	"net"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/inovacc/unravel-oss/pkg/knowledge/capture"
)

func TestPickFreePort_ReturnsListenablePort(t *testing.T) {
	port, err := capture.PickFreePort()
	if err != nil {
		t.Fatalf("PickFreePort: %v", err)
	}
	if port == 0 {
		t.Fatal("port=0 — expected ephemeral non-zero")
	}
	l, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		t.Fatalf("listen on assigned port %d: %v", port, err)
	}
	_ = l.Close()
}

func TestBuildLaunchCmd_TauriOnNonWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test verifies non-Windows refusal; skipping on windows")
	}
	_, err := capture.BuildLaunchCmd(capture.FrameworkTauri, "/bin/true", 1234, "/tmp/x")
	if !errors.Is(err, capture.ErrLiveCaptureUnsupported) {
		t.Fatalf("got %v, want ErrLiveCaptureUnsupported", err)
	}
}

func TestBuildLaunchCmd_UnknownFramework(t *testing.T) {
	_, err := capture.BuildLaunchCmd(capture.Framework("nope"), "/bin/true", 1234, "/tmp/x")
	if !errors.Is(err, capture.ErrLiveCaptureUnsupported) {
		t.Fatalf("got %v, want ErrLiveCaptureUnsupported", err)
	}
}

func TestRunLive_NonexistentApp(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := capture.RunLive(ctx, capture.Options{
		AppPath:   "/nonexistent/path/to/app/zzz",
		Framework: capture.FrameworkElectron,
		Timeout:   1 * time.Second,
	})
	if err == nil {
		t.Fatal("expected error for nonexistent app, got nil")
	}
}
