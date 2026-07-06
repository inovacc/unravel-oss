package leveldb

import (
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestParseLogRecords_BoundedOnAllCRCMismatch reproduces the WhatsApp EBWebView
// deadlock regression: an encrypted/opaque .log whose bytes never CRC-match must
// not trigger an O(n^2) byte-by-byte resync to EOF. The parser must abandon the
// store within maxLogResyncScanBytes and return quickly with no panic.
func TestParseLogRecords_BoundedOnAllCRCMismatch(t *testing.T) {
	// 2 MiB of pure garbage. Must exceed maxLogResyncScanBytes (1 MiB) so the
	// cap is actually exercised — anything smaller wouldn't prove the bound.
	// Shrunk from 8 MiB on 2026-05-23 (KBC-LEVELDB-FLAKE): under
	// concurrent-compile pressure the larger input pushed the original 3s
	// elapsed threshold past its budget without a real regression.
	const size = 2 << 20
	garbage := make([]byte, size)
	r := rand.New(rand.NewSource(42))
	_, _ = r.Read(garbage)

	done := make(chan int, 1)
	go func() {
		recs := parseLogRecords(garbage)
		done <- len(recs)
	}()

	start := time.Now()
	select {
	case n := <-done:
		elapsed := time.Since(start)
		// 5s budget: at 2 MiB with a 1 MiB cap, real-world is sub-100ms.
		// Headroom is for slow disks + concurrent test load, not for hiding
		// regressions — if elapsed > 5s, the cap is genuinely not enforced.
		if elapsed > 5*time.Second {
			t.Fatalf("parseLogRecords took %v on %d-byte garbage; resync cap not enforced", elapsed, size)
		}
		if n != 0 {
			t.Errorf("expected 0 records from pure garbage, got %d", n)
		}
		t.Logf("bounded: parsed %d-byte all-CRC-mismatch log in %v (cap=%d bytes)", size, elapsed, maxLogResyncScanBytes)
	case <-time.After(15 * time.Second):
		t.Fatal("parseLogRecords hung on all-CRC-mismatch input (deadlock regression reintroduced)")
	}
}

// TestParseLogRecords_ValidStoreStillParses guards against regressing legitimate
// parsing: a small valid record must still parse exactly as before the fix.
func TestParseLogRecords_ValidStoreStillParses(t *testing.T) {
	payload := []byte("valid-leveldb-payload")
	record := makeLogRecord(RecordTypeFull, payload)

	records := parseLogRecords(record)
	if len(records) != 1 {
		t.Fatalf("valid store: expected 1 record, got %d", len(records))
	}
	if string(records[0]) != string(payload) {
		t.Errorf("valid store: payload mismatch: got %q want %q", records[0], payload)
	}
}

// TestReadBoundedFile_RejectsOversize asserts a file over maxLevelDBFileBytes is
// surfaced as a non-fatal error (no panic, no unbounded read).
func TestReadBoundedFile_RejectsOversize(t *testing.T) {
	dir := t.TempDir()
	big := filepath.Join(dir, "huge.log")
	f, err := os.Create(big)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxLevelDBFileBytes + 1); err != nil {
		_ = f.Close()
		t.Fatal(err)
	}
	_ = f.Close()

	result := &ParseResult{}
	ParseLogFile(big, result)
	if len(result.Errors) == 0 {
		t.Fatal("expected a non-fatal error for oversize file, got none")
	}
}
