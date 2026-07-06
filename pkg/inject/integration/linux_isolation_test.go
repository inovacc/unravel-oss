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

// TestLinuxDoesNotImportMacOS is the CI gate from Phase 25 D-22/D-23.
// It walks pkg/inject/linux/*.go (including _test.go) and fails if any
// file imports unravel/pkg/inject/macos. Sibling of Phase 24's
// TestMacOSDoesNotImportLinux.
func TestLinuxDoesNotImportMacOS(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	linuxDir := filepath.Join(wd, "..", "linux")
	if _, err := os.Stat(linuxDir); err != nil {
		t.Fatalf("linux dir not found: %v", err)
	}

	fset := token.NewFileSet()
	err = filepath.Walk(linuxDir, func(p string, fi os.FileInfo, err error) error {
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
			if path == "github.com/inovacc/unravel-oss/pkg/inject/macos" ||
				strings.HasPrefix(path, "github.com/inovacc/unravel-oss/pkg/inject/macos/") {
				t.Errorf("%s imports forbidden package %q", p, path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
