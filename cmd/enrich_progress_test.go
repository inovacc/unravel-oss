/*
Copyright (c) 2026 Security Research
*/

package cmd

import "testing"

// TestEnrichProgressEvery covers the small progress-cadence helper that
// outlived the legacy `knowledge enrich` CLI command. Other knowledge
// subcommands (synth-names, topics) still use it for their progress
// reporting.
func TestEnrichProgressEvery(t *testing.T) {
	if !enrichProgressEvery(10, 10, 100) {
		t.Fatal("should log at the every-th item")
	}
	if !enrichProgressEvery(100, 10, 100) {
		t.Fatal("should log when done == total")
	}
	if enrichProgressEvery(3, 10, 100) {
		t.Fatal("should not log between cadence boundaries")
	}
	if enrichProgressEvery(0, 10, 100) {
		t.Fatal("done==0 must not log even though 0 mod every == 0")
	}
	if enrichProgressEvery(10, 0, 100) {
		t.Fatal("every==0 must be a no-op")
	}
}
