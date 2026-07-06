//go:build integration

package fsutil

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestRoundTripMaxLengthKsID ensures EncodeKsID + WrapLongPath let us create,
// write, and read back a file under a max-length ks_id directory. On Windows
// the path is wrapped with \\?\ so MAX_PATH cannot bite.
func TestRoundTripMaxLengthKsID(t *testing.T) {
	kbID := "aaaa1111aaaa1111"
	version := strings.Repeat("v", 200)
	capturedAt := "1714694400"
	ksID := kbID + ":" + version + ":" + capturedAt

	encoded, err := EncodeKsID(ksID)
	if err != nil {
		t.Fatalf("EncodeKsID: %v", err)
	}

	root := t.TempDir()
	// Nest deeply to push the full path past 247 chars on Windows.
	deep := filepath.Join(root,
		strings.Repeat("d", 40),
		strings.Repeat("e", 40),
		strings.Repeat("f", 40),
		"apps", kbID, "versions", encoded,
	)
	wrapped := WrapLongPath(deep)

	if runtime.GOOS == "windows" && len(deep) > 247 {
		if !strings.HasPrefix(wrapped, `\\?\`) {
			t.Fatalf("expected \\\\?\\ prefix on long windows path; got %q", wrapped[:20])
		}
	}

	if err := os.MkdirAll(wrapped, 0o755); err != nil {
		t.Fatalf("MkdirAll(%q): %v", wrapped, err)
	}

	payload := bytes.Repeat([]byte("u"), 32)
	filePath := filepath.Join(wrapped, "snapshot.bin")
	if err := os.WriteFile(filePath, payload, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	got, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch: got %d bytes want %d", len(got), len(payload))
	}
}
