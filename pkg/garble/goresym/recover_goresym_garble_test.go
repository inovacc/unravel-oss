//go:build goresym

package goresym_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/garble/goresym"
)

// garbledELF is a committed garble-obfuscated (default `garble build`) Go ELF
// fixture. Unlike a plain `-s -w` stripped binary, garble relocates/obfuscates
// the pclntab+moduledata, which defeats GoReSym v1.7.1's pclntab signature
// scan on Go 1.26 targets. See testdata/README.md for full provenance and
// docs/design/2026-goresym-backend.md §O1 for the recovery characterization.
const garbledELF = "app_linux_garbled"

// TestRecover_LiveGarbledELF characterizes GoReSym recovery on a genuinely
// garble-obfuscated binary — the headline mission target, distinct from the
// merely-stripped app_linux_stripped fixture.
//
// Documented boundary (GoReSym v1.7.1 + Go 1.26.4, garble v0.16.0):
//   - A plain `-s -w` stripped binary of the SAME source recovers 136 user
//     functions including main.main (see TestRecover_LiveStrippedELF).
//   - The garbled binary recovers NOTHING: GoReSym fails with
//     "failed to locate pclntab" because garble's obfuscation defeats the
//     pclntab signature scan. This is a real wrapped error (NOT the
//     ErrNotImplemented sentinel), so the dissect pipeline records it in
//     r.Errors and continues — the documented graceful-degrade contract.
//
// The test asserts that current boundary, but is forward-compatible: if a
// newer GoReSym learns to parse this binary, it records the recovery instead
// of failing (so a future tool bump turns this into a passing characterization
// rather than a red regression).
func TestRecover_LiveGarbledELF(t *testing.T) {
	if _, err := goresym.LookupGoresymForTest(); err != nil {
		t.Skip("GoReSym executable not on PATH; skipping live garble recovery test")
	}

	path := filepath.Join("testdata", garbledELF)
	res, err := goresym.Recover(context.Background(), path, goresym.Options{})

	if err != nil {
		// Expected today: garble defeats the pclntab locate. The error must be
		// a real wrapped error so callers surface it, NOT ErrNotImplemented
		// (which means "tool absent" and is reserved for a clean skip).
		if errors.Is(err, goresym.ErrNotImplemented) {
			t.Fatalf("garbled fixture returned ErrNotImplemented; want a real recovery error (tool IS present)")
		}
		t.Logf("characterization: GoReSym could not recover from the garbled "+
			"fixture (err=%v) — expected with GoReSym v1.7.1 + Go 1.26 + garble; "+
			"see docs/design/2026-goresym-backend.md §O1", err)
		return
	}

	// Forward-compatible branch: a future GoReSym recovered something. Record
	// what survived obfuscation so the §O1 boundary can be revisited.
	if res == nil {
		t.Fatal("Recover returned nil result and nil error")
	}
	t.Logf("characterization: a newer GoReSym recovered %d symbols / %d types "+
		"from the garbled fixture (GoVersion=%s) — §O1 boundary has moved; "+
		"update the design doc", len(res.Symbols), len(res.Types), res.GoVersion)
}
