/*
Copyright (c) 2026 Security Research
*/
package clr_test

import (
	"go/build"
	"strings"
	"testing"
)

// d09: no internal/ai import may appear anywhere under pkg/dotnet/clr/...
func TestCLR_NoInternalAIImport(t *testing.T) {
	for _, pkg := range []string{
		"github.com/inovacc/unravel-oss/pkg/dotnet/clr",
		"github.com/inovacc/unravel-oss/pkg/dotnet/clr/metadata",
		"github.com/inovacc/unravel-oss/pkg/dotnet/clr/sig",
		"github.com/inovacc/unravel-oss/pkg/dotnet/clr/il",
	} {
		p, err := build.Import(pkg, "", build.ImportComment)
		if err != nil {
			t.Fatalf("import %s: %v", pkg, err)
		}
		for _, imp := range p.Imports {
			if strings.Contains(imp, "internal/ai") {
				t.Fatalf("%s imports forbidden %s (d09 violation)", pkg, imp)
			}
		}
	}
}
