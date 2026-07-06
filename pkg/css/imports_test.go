/*
Copyright (c) 2026 Security Research
*/
package css

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestImportResolveInline(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "reset.css"), []byte("* { margin: 0; }"), 0644)
	_ = os.WriteFile(filepath.Join(dir, "main.css"), []byte("@import './reset.css';\n.app { color: red; }"), 0644)

	r := NewImportResolver(dir, "")
	content, err := r.Resolve(filepath.Join(dir, "main.css"))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !strings.Contains(string(content), "margin: 0") {
		t.Error("expected inlined reset.css content")
	}
	if !strings.Contains(string(content), "color: red") {
		t.Error("expected main.css content preserved")
	}
}

func TestImportResolveCycleDetection(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "a.css"), []byte("@import './b.css';\n.a {}"), 0644)
	_ = os.WriteFile(filepath.Join(dir, "b.css"), []byte("@import './a.css';\n.b {}"), 0644)

	r := NewImportResolver(dir, "")
	_, err := r.Resolve(filepath.Join(dir, "a.css"))
	if err == nil {
		t.Fatal("expected cycle detection error")
	}
	if !strings.Contains(err.Error(), "import cycle") {
		t.Errorf("expected 'import cycle' in error, got: %v", err)
	}
}

func TestImportResolveNodeModules(t *testing.T) {
	dir := t.TempDir()
	nm := filepath.Join(dir, "node_modules", "normalize.css")
	_ = os.MkdirAll(nm, 0755)
	_ = os.WriteFile(filepath.Join(nm, "index.css"), []byte("html { line-height: 1.15; }"), 0644)
	_ = os.WriteFile(filepath.Join(dir, "main.css"), []byte("@import 'normalize.css';\n.app {}"), 0644)

	r := NewImportResolver(dir, filepath.Join(dir, "node_modules"))
	content, err := r.Resolve(filepath.Join(dir, "main.css"))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !strings.Contains(string(content), "line-height") {
		t.Error("expected node_modules content inlined")
	}
}

func TestImportResolveGraph(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "base.css"), []byte("body { font: sans-serif; }"), 0644)
	_ = os.WriteFile(filepath.Join(dir, "theme.css"), []byte("@import './base.css';\n:root { --color: blue; }"), 0644)
	_ = os.WriteFile(filepath.Join(dir, "main.css"), []byte("@import './theme.css';\n.app { color: var(--color); }"), 0644)

	r := NewImportResolver(dir, "")
	_, err := r.Resolve(filepath.Join(dir, "main.css"))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	graph := r.Graph()
	if graph == nil {
		t.Fatal("expected non-nil graph")
	}
	mainKey := filepath.Join(dir, "main.css")
	deps, ok := graph[mainKey]
	if !ok {
		t.Fatalf("expected main.css in graph, keys: %v", graphKeys(graph))
	}
	if len(deps) != 1 {
		t.Errorf("expected 1 dep for main.css, got %d", len(deps))
	}
}

func TestImportResolveRecursive(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "c.css"), []byte(".c { display: block; }"), 0644)
	_ = os.WriteFile(filepath.Join(dir, "b.css"), []byte("@import './c.css';\n.b { display: flex; }"), 0644)
	_ = os.WriteFile(filepath.Join(dir, "a.css"), []byte("@import './b.css';\n.a { display: grid; }"), 0644)

	r := NewImportResolver(dir, "")
	content, err := r.Resolve(filepath.Join(dir, "a.css"))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	s := string(content)
	if !strings.Contains(s, "display: block") {
		t.Error("expected c.css content (transitive)")
	}
	if !strings.Contains(s, "display: flex") {
		t.Error("expected b.css content")
	}
	if !strings.Contains(s, "display: grid") {
		t.Error("expected a.css content")
	}
}

func TestImportResolveURLImportsSkipped(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "main.css"), []byte("@import url('https://fonts.example.com/font.css');\n.app {}"), 0644)

	r := NewImportResolver(dir, "")
	content, err := r.Resolve(filepath.Join(dir, "main.css"))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	// URL imports should be preserved as-is
	if !strings.Contains(string(content), "https://fonts.example.com") {
		t.Error("expected URL import to be preserved")
	}
}

func graphKeys(m map[string][]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
