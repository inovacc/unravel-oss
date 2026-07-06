/*
Copyright (c) 2026 Security Research
*/

// Package debug is the transpiler-pipeline diagnostic-recording SEAM (D-42).
//
// IMPORTANT — currently a NO-OP STUB. Despite the type and method names
// (RecordAST, RecordIR, RecordCodegenOutput, Finish, …), this package does
// NOT yet dump any intermediate AST / IR / codegen artifacts to disk:
// FileRecorder's Record*/Start/SetMode bodies are empty and Finish() always
// returns nil (see file_recorder.go). New() is a test shim that ignores its
// rootDir/logger arguments. The seam exists so the converter pipeline can be
// wired for recording (via converter.WithDebug) without crashing, but no
// transpile-core artifacts are written today.
//
// The `unravel transpile` command does not even wire --debug into the
// converter, so `transpile --debug` records nothing at this layer. The root
// --debug flag's "dump all intermediate artifacts" help describes the SEPARATE
// pkg/debug recorder used by `unravel dissect`, which does write artifacts.
//
// Real transpile-core artifact dumping is deferred future work, tracked in
// docs/BACKLOG.md (TRANSPILE-DEBUG-NOOP). Do not assume these methods persist
// anything until that item is implemented.
//
// NOTE: commit 6f776378's message "restore missing debug package stubs" is
// misleading — there was never a prior real implementation at this layer.
package debug

// Recorder is the top-level debug session manager.
type Recorder struct {
	enabled bool
}

// NopRecorder returns a disabled recorder that drops all output.
func NopRecorder() *Recorder {
	return &Recorder{enabled: false}
}

// New creates an "enabled" recorder. NOTE: this is a test shim — rootDir and
// logger are intentionally ignored and no debug/ directory is created. An
// enabled recorder still records nothing to disk because the FileRecorder
// Record*/Finish methods are no-ops (see the package doc + file_recorder.go).
func New(rootDir string, logger any) (*Recorder, error) {
	return &Recorder{enabled: true}, nil
}

// Enabled returns true if this recorder is capturing artifacts.
func (r *Recorder) Enabled() bool {
	return r.enabled
}

// FileRecorder creates a scoped recorder for a specific input file.
func (r *Recorder) FileRecorder(filename string) *FileRecorder {
	return &FileRecorder{
		recorder: r,
		filename: filename,
	}
}
