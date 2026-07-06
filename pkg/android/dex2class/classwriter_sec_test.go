package dex2class

import (
	"testing"
)

// TestAddUTF8_PoolOverflowGuard verifies that addUTF8 returns 0 (safe sentinel)
// rather than wrapping the uint16 pool index when the pool is full.
func TestAddUTF8_PoolOverflowGuard(t *testing.T) {
	cw := newClassWriter()

	// Fill the pool up to maxPoolEntries by adding unique strings.
	// newClassWriter pre-populates index 0 (unused), so the pool starts at len=1.
	// We need to reach len(cw.pool) >= maxPoolEntries = 65535.
	for i := len(cw.pool); i < maxPoolEntries; i++ {
		// Use a unique string per entry to avoid deduplication.
		s := string([]byte{byte(i & 0xFF), byte((i >> 8) & 0xFF), byte((i >> 16) & 0xFF)})
		cw.addUTF8(s)
	}

	if len(cw.pool) < maxPoolEntries {
		t.Fatalf("pool did not reach capacity: len=%d want>=%d", len(cw.pool), maxPoolEntries)
	}

	// The next unique addition must return 0 (overflow guard).
	idx := cw.addUTF8("__overflow_sentinel__")
	if idx != 0 {
		t.Errorf("expected addUTF8 to return 0 at pool capacity, got %d", idx)
	}

	// Pool size must not have grown beyond maxPoolEntries.
	if len(cw.pool) > maxPoolEntries {
		t.Errorf("pool grew past maxPoolEntries: len=%d", len(cw.pool))
	}
}

// TestAddUTF8_Deduplication verifies that identical strings share the same index.
func TestAddUTF8_Deduplication(t *testing.T) {
	cw := newClassWriter()
	idx1 := cw.addUTF8("hello")
	idx2 := cw.addUTF8("hello")
	if idx1 != idx2 {
		t.Errorf("expected same index for duplicate UTF-8: got %d and %d", idx1, idx2)
	}
}
