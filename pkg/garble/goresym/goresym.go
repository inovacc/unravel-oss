// Package goresym is a Go-binary symbol-recovery layer that wraps two
// upstream tools — Mandiant's GoReSym (https://github.com/mandiant/GoReSym)
// and goretk/redress (https://github.com/goretk/redress) — to recover
// function names, type names, and PCLN data from stripped or garbled
// Go binaries.
//
// pkg/garble already detects garble-style obfuscation; this package
// closes the gap by attempting to *un-mangle* the binary back into a
// browseable symbol set.
//
// Status: the Recover() implementation is split by build tag. The
// default tool-free build (recover_default.go) returns the
// ErrNotImplemented sentinel; the `goresym` build tag selects a
// shell-out backend (recover_goresym.go) that drives Mandiant's GoReSym
// CLI. Production code MUST check for the ErrNotImplemented sentinel —
// it is the normal default-build state and also the runtime signal that
// the external tool is not on PATH. See the BACKLOG entry "Go-Binary
// Symbol Recovery (2026-04-26 reference capture)" and
// docs/design/2026-goresym-backend.md for the decision record.
//
// Both recovery paths are IMPLEMENTED via the shell-out backend, each
// with a documented tool-version limitation:
//
//   - Function/PCLN recovery: the GoReSym backend enumerates the
//     pclntab/PCLN and populates Result.Symbols. Verified end-to-end
//     against non-stripped and stripped-ELF binaries. It recovers
//     NOTHING from garble-obfuscated binaries, because garble strips the
//     pclntab signature the GoReSym scan relies on — see
//     docs/design/2026-goresym-backend.md §O1.
//   - Type recovery: GoReSym's `-t` mode walks moduledata
//     typelinks→Types and itablinks→Interfaces, feeding Result.Types
//     onward to the KB RecoveredTypes path. Verified end-to-end, BUT
//     GoReSym v1.7.1 emits null Types for Go 1.26 binaries (moduledata
//     layout drift — a tool-version gap, not a wiring gap) — see §O3.
//
// TODO(goresym): future work tracked as follow-ups, not part of the
// shipped backend:
//
//  1. Pure-Go reimplementation. Vendor the relevant Mandiant code (under
//     its MIT license) into pkg/garble/goresym/internal so the unravel
//     binary stays single-file and works on offline/airgapped analyst
//     boxes. Effort: large — GoReSym forks Go's debug/* and runtime
//     internals (~27k LOC of moduledata parsing, far above the early
//     estimate) and must track Go format drift. Tracked under the
//     "Go-Binary Symbol Recovery" BACKLOG item (pure-Go vendor follow-up).
//
//  2. GoReSym version bump to restore Go 1.26 type output once upstream
//     ships moduledata support past v1.7.1 — see §O3.
package goresym

import (
	"errors"
)

// ErrNotImplemented signals that Recover was called before a real
// backend is available. Callers should compare with errors.Is and either
// fall back to the pkg/garble heuristic mode or skip the analysis.
var ErrNotImplemented = errors.New("goresym: symbol recovery not implemented yet — see BACKLOG / pkg/garble/goresym")

// Symbol is one recovered (name, address) tuple from the binary's
// PCLN/moduledata. Type is the Go type name when known.
type Symbol struct {
	Name    string `json:"name"`
	Address uint64 `json:"address"`
	Type    string `json:"type,omitempty"`
}

// Result holds everything Recover surfaces about a single binary.
type Result struct {
	BuildID    string   `json:"build_id,omitempty"`
	GoVersion  string   `json:"go_version,omitempty"`
	ModulePath string   `json:"module_path,omitempty"`
	Symbols    []Symbol `json:"symbols,omitempty"`
	Types      []string `json:"types,omitempty"`
}

// Options tunes Recover. Backend selects between pure-Go and shell-out
// modes; "" lets the package pick the best available backend.
type Options struct {
	Backend       string // "", "pure", "goresym", "redress"
	IncludeStdLib bool   // include runtime / stdlib symbols (default: skip)
	// GoVersion, when non-empty, is passed to GoReSym via -v to help it
	// locate the pclntab on stripped binaries, notably PE (Windows)
	// targets where signature scanning alone can fail. Callers typically
	// thread the version already extracted by garble.ExtractInfo.
	GoVersion string
}

// Recover analyses the binary at path and returns the recovered symbol
// set. Its implementation is selected by build tag: the default
// tool-free build returns ErrNotImplemented (recover_default.go); the
// `goresym` build tag drives the GoReSym CLI (recover_goresym.go).
