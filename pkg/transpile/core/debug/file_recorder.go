/*
Copyright (c) 2026 Security Research
*/

package debug

// FileRecorder tracks the pipeline stages for a single file.
type FileRecorder struct {
	recorder *Recorder
	filename string
	err      error
	fallback bool
	output   string
}

// SetError records a fatal pipeline error for this unit.
func (f *FileRecorder) SetError(err error) {
	if f.recorder.enabled {
		f.err = err
	}
}

// The Record*/Start/SetMode/Finish methods below are intentionally NO-OPS:
// transpile-core artifact dumping is not yet implemented. They satisfy the
// converter's recording seam without persisting anything. Finish() therefore
// always returns nil (nothing was buffered to flush). See the package doc and
// docs/BACKLOG.md (TRANSPILE-DEBUG-NOOP) before assuming these write to disk.
func (f *FileRecorder) Start()                                      {}             // no-op stub
func (f *FileRecorder) SetMode(mode string)                         {}             // no-op stub
func (f *FileRecorder) RecordInput(path string, input []byte)       {}             // no-op stub
func (f *FileRecorder) RecordIncludes(includes []string, err error) {}             // no-op stub
func (f *FileRecorder) Finish() error                               { return nil } // no-op stub
func (f *FileRecorder) RecordSystemPrompt(prompt string)            {}             // no-op stub
func (f *FileRecorder) RecordUserPrompt(prompt string)              {}             // no-op stub
func (f *FileRecorder) RecordAST(ast any)                           {}             // no-op stub
func (f *FileRecorder) RecordIR(ir any)                             {}             // no-op stub
func (f *FileRecorder) RecordAdaptedIR(ir any)                      {}             // no-op stub

// SetLLMFallback records whether this unit triggered an LLM prompt fallback.
func (f *FileRecorder) SetLLMFallback(b bool) {
	if f.recorder.enabled {
		f.fallback = b
	}
}

// RecordCodegenOutput records the final deterministic Go source string.
func (f *FileRecorder) RecordCodegenOutput(s string) {
	if f.recorder.enabled {
		f.output = s
	}
}

// ErrorString returns the recorded error as a string, or an empty string if none.
func (f *FileRecorder) ErrorString() string {
	if f.err == nil {
		return ""
	}
	return f.err.Error()
}
