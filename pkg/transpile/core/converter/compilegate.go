package converter

import (
	"fmt"
	"go/parser"
	"go/token"
)

// assertGoParses is the post-codegen compile gate (TRANSPILE-PHASE2-GAPS "C7",
// Tier 1). It runs go/parser over the EMITTED Go source — not the ANTLR input
// front-end — so a codegen bug that produces syntactically invalid Go is caught
// and surfaced instead of silently passing the coverage metric.
//
// It is intentionally a pure-stdlib SYNTACTIC gate: no module context, no
// network, no `go build` subprocess, so it stays deterministic and hermetic.
// parser.AllErrors makes the returned error report every fault (with file
// position) rather than stopping at the first, so operators get the location.
// A deeper go/types type-check or temp-module `go build` is a possible
// follow-up (Tier 2/3) but is out of scope here because the emitted unit is a
// single file with unresolved external imports.
func assertGoParses(src []byte) error {
	fset := token.NewFileSet()

	if _, err := parser.ParseFile(fset, "output.go", src, parser.AllErrors); err != nil {
		return fmt.Errorf("generated Go failed to parse: %w", err)
	}

	return nil
}
