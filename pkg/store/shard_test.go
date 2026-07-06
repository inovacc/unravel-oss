/*
Copyright (c) 2026 Security Research
*/
package store

import "testing"

func TestShardFor(t *testing.T) {
	// Two hex chars (one byte -> 256 buckets).
	s := shardFor("019e3ce1-9a23-7c1c-b16a-79c4b0180000")
	if len(s) != 2 {
		t.Fatalf("shardFor = %q, want length 2", s)
	}

	// Deterministic.
	if shardFor("abc") != shardFor("abc") {
		t.Error("shardFor not deterministic")
	}

	// Must NOT key on the uuidv7 prefix (a near-constant ms timestamp). 1000
	// sequential uuidv7 ids must spread across many buckets, not collapse into
	// one or two as a prefix-keyed shard would.
	seen := map[string]int{}
	for range 1000 {
		seen[shardFor(newUUIDv7())]++
	}
	if len(seen) < 100 {
		t.Errorf("poor shard spread: %d distinct buckets over 1000 ids (want >=100) - prefix-keyed?", len(seen))
	}
}
