package lower

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/transpile/core/codegen"
	pyparser "github.com/inovacc/unravel-oss/pkg/transpile/languages/python/parser"
)

// repoRoot walks up from this test file to the module root.
func repoRoot(t *testing.T) string {
	t.Helper()

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}

	// .../internal/languages/python/lower/realproject_test.go → up 5
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", ".."))
}

// TestRealProjectGoIsParseable verifies that the structured deterministic
// pipeline emits Go that the Go parser accepts for the ecommerce sample
// files that lower without LLM-only constructs. This is the real success
// gate: structured control flow must produce syntactically valid Go, not a
// flattened RawStmt blob.
func TestRealProjectGoIsParseable(t *testing.T) {
	root := repoRoot(t)

	// mustParse files are enforced regressions: their generated Go must stay
	// syntactically valid. Others are tracked (logged) until their phase lands.
	mustParse := map[string]bool{"models.py": true, "repository.py": true}

	for _, name := range []string{"models.py", "repository.py"} {

		t.Run(name, func(t *testing.T) {
			path := filepath.Join(root, "test_scenarios", "python", "19_ecommerce", name)

			src, err := os.ReadFile(path)
			if err != nil {
				t.Skipf("sample not found: %v", err)
			}

			mod, err := pyparser.New().ParseFile(name, src)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}

			irMod, err := NewLowerer().Lower(mod)
			if err != nil {
				t.Fatalf("lower: %v", err)
			}

			goSrc, err := codegen.New().Generate(irMod)
			if err != nil {
				t.Fatalf("codegen: %v", err)
			}

			// Structural gate (this PR's scope): control flow must be lowered
			// to real Go, NOT a flattened RawStmt blob. Regression guard for
			// the "parser discards statement structure" defect.
			if strings.Contains(goSrc, "Python if statement") ||
				strings.Contains(goSrc, "Python for statement") ||
				strings.Contains(goSrc, "Python while statement") {
				t.Fatalf("%s: control flow still flattened to RawStmt blob:\n%s", name, goSrc)
			}

			// Parse gate: enforced for mustParse files, tracked for the rest.
			fset := token.NewFileSet()
			_, perr := parser.ParseFile(fset, name+".go", goSrc, parser.AllErrors)

			switch {
			case perr == nil:
				t.Logf("%s: fully parseable Go ✓", name)
			case mustParse[name]:
				t.Fatalf("%s: REGRESSION — generated Go no longer parses: %v\n%s", name, perr, goSrc)
			default:
				t.Logf("%s: not yet fully compilable (expression-lowering phase pending): %v", name, perr)
			}
		})
	}
}
