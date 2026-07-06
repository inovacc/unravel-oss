/*
Copyright (c) 2026 Security Research
*/
package visual

import (
	"bytes"
	"context"
	"image/png"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/capture/cdp"
)

func TestScreenshotWrapper(t *testing.T) {
	if NumActiveDisplays() == 0 {
		t.Skip("no active displays (headless CI)")
	}
	out, w, h, err := CaptureScreen(0)
	if err != nil {
		t.Fatalf("CaptureScreen: %v", err)
	}
	if w == 0 || h == 0 {
		t.Fatalf("zero bounds: %dx%d", w, h)
	}
	if _, err := png.Decode(bytes.NewReader(out)); err != nil {
		t.Fatalf("png.Decode: %v", err)
	}
}

func TestContentProtectedReturns(t *testing.T) {
	// On both Windows and non-Windows, calling with hwnd=0 must not panic and
	// must return without error (Windows path returns false on bad hwnd).
	got, err := ContentProtected(0)
	if err != nil {
		t.Fatalf("ContentProtected(0): %v", err)
	}
	if got {
		t.Errorf("expected false for invalid hwnd 0, got true")
	}
}

func TestWriteLatestPointer(t *testing.T) {
	kb := t.TempDir()
	runID := "2026-04-27T12-34-56Z"
	if err := WriteLatestPointer(kb, runID); err != nil {
		t.Fatalf("WriteLatestPointer: %v", err)
	}
	link := filepath.Join(kb, "visual", "latest")
	txt := filepath.Join(kb, "visual", "latest.txt")

	if runtime.GOOS == "windows" {
		// Either symlink succeeded (Developer Mode) OR latest.txt fallback.
		if _, err := os.Lstat(link); err == nil {
			info, _ := os.Lstat(link)
			if info.Mode()&os.ModeSymlink != 0 {
				target, err := os.Readlink(link)
				if err != nil {
					t.Fatalf("readlink: %v", err)
				}
				if target != runID {
					t.Errorf("expected target %q, got %q", runID, target)
				}
				return
			}
		}
		// Fallback file must exist with runID.
		got, err := os.ReadFile(txt)
		if err != nil {
			t.Fatalf("expected fallback latest.txt: %v", err)
		}
		if string(got) != runID {
			t.Errorf("expected %q, got %q", runID, string(got))
		}
	} else {
		target, err := os.Readlink(link)
		if err != nil {
			t.Fatalf("readlink: %v", err)
		}
		if target != runID {
			t.Errorf("expected target %q, got %q", runID, target)
		}
	}
}

func TestWriteLatestPointerRejectsBadSlug(t *testing.T) {
	kb := t.TempDir()
	for _, bad := range []string{"", "..", ".", "a/b", "a\\b"} {
		if err := WriteLatestPointer(kb, bad); err == nil {
			t.Errorf("expected error for slug %q, got nil", bad)
		}
	}
}

func TestOrchestratorModeDispatcher(t *testing.T) {
	// Wave-1 stub validation has been replaced by Wave-2 mode-specific tests
	// (TestPerStateCapture_Auto, TestScriptedModeReplay). With real bodies
	// in place, this test only verifies the dispatcher itself routes by mode
	// without panicking. ScriptedMode with empty ScenarioPath returns a fast
	// error; Auto/Interactive require a live CDP and are exercised elsewhere.
	cli := cdp.New("", nil, nil)
	o, err := New(cli, Options{Mode: ModeScripted})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := o.Run(context.Background()); err == nil {
		t.Errorf("Run(scripted, no scenario): expected error, got nil")
	}
}

func TestOrchestratorUnknownMode(t *testing.T) {
	cli := cdp.New("", nil, nil)
	o := &Orchestrator{cli: cli, opts: Options{Mode: Mode("bogus")}}
	if err := o.Run(context.Background()); err == nil {
		t.Fatal("expected error for unknown mode")
	}
}

func TestOrchestratorRequiresClient(t *testing.T) {
	if _, err := New(nil, Options{}); err == nil {
		t.Fatal("expected error for nil client")
	}
}
