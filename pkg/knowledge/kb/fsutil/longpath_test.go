package fsutil

import (
	"runtime"
	"strings"
	"testing"
)

func TestWrapLongPath_Short(t *testing.T) {
	in := strings.Repeat("a", 100)
	got := WrapLongPath(in)
	if got != in {
		t.Fatalf("short path should be unchanged; got %q", got)
	}
}

func TestWrapLongPath_LongOnWindows(t *testing.T) {
	in := `C:\` + strings.Repeat("a", 248)
	got := WrapLongPath(in)
	if runtime.GOOS == "windows" {
		if !strings.HasPrefix(got, `\\?\`) {
			t.Fatalf("expected \\\\?\\ prefix on windows; got %q", got[:20])
		}
	} else {
		if got != in {
			t.Fatalf("non-windows: long path should be unchanged; got %q", got)
		}
	}
}

func TestWrapLongPath_AlreadyPrefixed(t *testing.T) {
	in := `\\?\C:\` + strings.Repeat("a", 300)
	got := WrapLongPath(in)
	if got != in {
		t.Fatalf("already-prefixed path should be unchanged; got %q", got)
	}
}
