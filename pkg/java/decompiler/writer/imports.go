package writer

import (
	"fmt"
	"slices"
	"strings"
)

// ImportTracker collects and manages Java import statements.
type ImportTracker struct {
	imports map[string]bool // fully-qualified class name → tracked
}

// NewImportTracker creates a new import tracker.
func NewImportTracker() *ImportTracker {
	return &ImportTracker{imports: make(map[string]bool)}
}

// Add registers a fully-qualified class name as an import.
// java.lang.* imports are not tracked (they are auto-imported in Java).
func (it *ImportTracker) Add(fqn string) {
	if fqn == "" || !strings.Contains(fqn, ".") {
		return
	}
	// java.lang.* is auto-imported
	pkg := packageName(fqn)
	if pkg == "java.lang" {
		return
	}

	it.imports[fqn] = true
}

// Imports returns the sorted list of import statements.
func (it *ImportTracker) Imports() []string {
	result := make([]string, 0, len(it.imports))
	for fqn := range it.imports {
		result = append(result, fqn)
	}

	slices.Sort(result)

	return result
}

// WriteImports returns the import block as a string.
func (it *ImportTracker) WriteImports() string {
	imports := it.Imports()
	if len(imports) == 0 {
		return ""
	}

	var b strings.Builder
	for _, imp := range imports {
		_, _ = fmt.Fprintf(&b, "import %s;\n", strings.ReplaceAll(imp, "$", "."))
	}

	return b.String()
}

// HasImports returns true if there are any imports tracked.
func (it *ImportTracker) HasImports() bool {
	return len(it.imports) > 0
}

// packageName extracts the package from a fully-qualified class name.
func packageName(fqn string) string {
	if idx := strings.LastIndex(fqn, "."); idx >= 0 {
		return fqn[:idx]
	}

	return ""
}
