package backfill

import (
	"strings"
	"testing"

	// side-effect: registers all lang extractors (js, ts, go, c, csharp, java, etc.)
	_ "github.com/inovacc/unravel-oss/pkg/knowledge/kb/langs"
)

func TestExtract_EmptyBody(t *testing.T) {
	imports, symbolsJSON, err := Extract([]byte{}, "unknown.xyz", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(imports) != 0 {
		t.Errorf("expected no imports, got %v", imports)
	}
	// Empty body → empty or valid JSON, never panic.
	_ = symbolsJSON
}

func TestExtract_JSImport(t *testing.T) {
	body := []byte(`import x from "./y";
import { foo } from "../bar";
function hello() { return 1; }
`)
	imports, _, err := Extract(body, "bundle.js", "js")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, imp := range imports {
		if imp == "./y" || strings.Contains(imp, "y") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected import './y' in %v", imports)
	}
}

func TestExtract_JSKeywordsNotInSymbols(t *testing.T) {
	// A body that contains only a switch/return structure — keywords should
	// NOT appear in the extracted symbols_json methods list.
	body := []byte(`function f(x) {
	switch(x) {
		case 1: return "a";
		case 2: return "b";
	}
}`)
	_, symbolsJSON, err := Extract(body, "app.js", "js")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, kw := range []string{`"return"`, `"switch"`, `"case"`} {
		if strings.Contains(symbolsJSON, kw) {
			t.Errorf("keyword %s should not appear in symbolsJSON: %s", kw, symbolsJSON)
		}
	}
}

func TestExtract_NameFallback(t *testing.T) {
	// Name with .js extension, lang field empty — should route to JS extractor.
	body := []byte(`const VERSION = "1.0.0";`)
	_, symbolsJSON, err := Extract(body, "config.js", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should not panic. symbolsJSON may be empty or contain VERSION.
	_ = symbolsJSON
}

func TestExtract_UnknownExtension_NoError(t *testing.T) {
	body := []byte("some binary data \x00\x01\x02")
	imports, symbolsJSON, err := Extract(body, "module.wasm", "")
	if err != nil {
		t.Fatalf("unexpected error on unknown extension: %v", err)
	}
	// Generic extractor: no imports, no symbols.
	if len(imports) != 0 {
		t.Errorf("expected no imports from unknown ext, got %v", imports)
	}
	_ = symbolsJSON
}
