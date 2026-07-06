package converter

import (
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/transpile/audit"
	"github.com/inovacc/unravel-oss/pkg/transpile/core/debug"
)

func guardTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// TestGuardStagePanicSurfacesStructuredError is the D-03 / SC3 invariant test:
// a panic inside a guarded stage MUST become a non-nil structured error that is
// surfaced via fr.SetError AND Auditor.AddError. It must NEVER be swallowed
// (the guard must not `return nil`) — a recovered unit that emits neither
// output nor an audit error is a silent-failure violation (T-08-06).
func TestGuardStagePanicSurfacesStructuredError(t *testing.T) {
	rec, err := debug.New(t.TempDir(), guardTestLogger())
	if err != nil {
		t.Fatalf("debug.New: %v", err)
	}

	fr := rec.FileRecorder("panic_unit.cpp")
	fr.Start()

	aud, err := audit.New(t.TempDir(), "guard-test", guardTestLogger())
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}

	gErr := guardStage("parse", fr, aud, func() error {
		panic("boom in parser")
	})

	// (a) panic converted to a non-nil structured error, not swallowed.
	if gErr == nil {
		t.Fatal("guardStage returned nil for a panicking fn — panic was SWALLOWED (silent failure, T-08-06)")
	}

	if !strings.Contains(gErr.Error(), "panic in parse") {
		t.Fatalf("error %q does not name the guarded stage", gErr.Error())
	}

	if !strings.Contains(gErr.Error(), "boom in parser") {
		t.Fatalf("error %q does not carry the original panic value", gErr.Error())
	}

	// (b) surfaced via fr.SetError (debug per-unit error).
	if got := fr.ErrorString(); got == "" {
		t.Fatal("fr.SetError was not called — recovered panic not surfaced to debug recorder (silent failure)")
	}

	// (b) surfaced via Auditor.AddError (run/audit trail).
	rep := aud.Report()
	if len(rep.Errors) == 0 {
		t.Fatal("Auditor.AddError was not called — recovered panic not surfaced to audit trail (silent failure)")
	}

	if !strings.Contains(rep.Errors[0], "panic in parse") {
		t.Fatalf("audit error %q does not carry the structured panic message", rep.Errors[0])
	}
}

// TestGuardStagePassThrough asserts the guard is transparent for the
// non-panicking path: it returns fn's error (or nil) unchanged and does not
// fabricate spurious audit errors.
func TestGuardStagePassThrough(t *testing.T) {
	aud, err := audit.New(t.TempDir(), "guard-test", guardTestLogger())
	if err != nil {
		t.Fatalf("audit.New: %v", err)
	}

	// nil pass-through.
	if got := guardStage("lower", nil, aud, func() error { return nil }); got != nil {
		t.Fatalf("guardStage wrapped a nil-returning fn into %v", got)
	}

	// error pass-through (unchanged identity).
	sentinel := errors.New("real lowering failure")
	got := guardStage("lower", nil, aud, func() error { return sentinel })

	if !errors.Is(got, sentinel) {
		t.Fatalf("guardStage altered a real error: got %v, want %v", got, sentinel)
	}

	// No panic occurred → no audit error fabricated.
	if rep := aud.Report(); len(rep.Errors) != 0 {
		t.Fatalf("guardStage fabricated audit errors on the non-panic path: %v", rep.Errors)
	}
}
