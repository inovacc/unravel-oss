/*
Copyright (c) 2026 Security Research
*/
package output

import (
	"bytes"
	"io"
	"os"
	"testing"
)

// captureStdout redirects os.Stdout for the duration of fn, then returns the
// captured output as a string.  It restores stdout even on panic.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}

	orig := os.Stdout
	os.Stdout = w

	defer func() {
		os.Stdout = orig
	}()

	fn()

	_ = w.Close()

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("io.Copy: %v", err)
	}
	_ = r.Close()

	return buf.String()
}
