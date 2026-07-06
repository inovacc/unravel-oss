/*
Copyright (c) 2026 Security Research
*/
package integration_test

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestMacOSDoesNotImportLinux is the CI gate from Phase 24 D-20/D-21. It
// walks pkg/inject/macos/*.go (including _test.go) and fails if any file
// imports unravel/pkg/inject/linux.
func TestMacOSDoesNotImportLinux(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	macosDir := filepath.Join(wd, "..", "macos")
	if _, err := os.Stat(macosDir); err != nil {
		t.Fatalf("macos dir not found: %v", err)
	}

	fset := token.NewFileSet()
	err = filepath.Walk(macosDir, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if fi.IsDir() || !strings.HasSuffix(p, ".go") {
			return nil
		}
		file, err := parser.ParseFile(fset, p, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imp := range file.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			if path == "github.com/inovacc/unravel-oss/pkg/inject/linux" ||
				strings.HasPrefix(path, "github.com/inovacc/unravel-oss/pkg/inject/linux/") {
				t.Errorf("%s imports forbidden package %q", p, path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
