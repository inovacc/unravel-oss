/*
Copyright (c) 2026 Security Research
*/
package migrate

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// repoRootForTest walks up from this test file to the repository root.
func repoRootForTest(t *testing.T) string {
	t.Helper()
	_, here, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(here)
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("could not locate repo root")
	return ""
}
