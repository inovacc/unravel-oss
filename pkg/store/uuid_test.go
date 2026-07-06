/*
Copyright (c) 2026 Security Research
*/
package store

import "testing"

// TestNewUUIDv7_Unique guards against the Windows entropy collapse fixed in
// this change: newUUIDv7 must produce distinct ids even in a tight loop. The
// old os.Open("/dev/urandom") path failed on Windows and fell back to the
// nanosecond clock, which barely advances between calls and collided heavily.
func TestNewUUIDv7_NoCollisionTightLoop(t *testing.T) {
	const n = 10000
	seen := make(map[string]struct{}, n)
	for range n {
		id := newUUIDv7()
		if _, dup := seen[id]; dup {
			t.Fatalf("duplicate id %q after %d unique (entropy collapse?)", id, len(seen))
		}
		seen[id] = struct{}{}
	}
	if len(seen) != n {
		t.Fatalf("got %d distinct ids, want %d", len(seen), n)
	}
}
