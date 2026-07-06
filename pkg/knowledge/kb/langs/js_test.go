package langs

import (
	"strings"
	"testing"
)

func TestExtractJSMinified(t *testing.T) {
	// Pad with no-op assignments so the single line is long enough to cross
	// the looksMinified threshold (minifiedMaxLine=2000, min body 512 bytes).
	pad := ""
	for len(pad) < 2100 {
		pad += "a=1;"
	}
	min := `function Aa(a){return a}` +
		`;class Bb{m(){}}` +
		`;var Cc=1;const Dd=2` +
		`;import X from"modx";require("modn");` + pad // one line, no leading newlines
	m, err := extractJS("/x.js", []byte(min))
	if err != nil {
		t.Fatal(err)
	}
	sym := map[string][]string{}
	mustUnmarshalSym(t, m.SymbolsJSON, &sym)
	want := map[string][]string{
		"functions": {"Aa"},
		"types":     {"Bb"},
		"consts":    {"Cc", "Dd"},
	}
	for k, ws := range want {
		for _, w := range ws {
			found := false
			for _, g := range sym[k] {
				if g == w {
					found = true
				}
			}
			if !found {
				t.Errorf("minified extract missing %s symbol %q (got %v)", k, w, sym[k])
			}
		}
	}
	// baseline: the raw (?m)^ regex pass alone misses these — documents the delta.
	raw, _ := regexExtract("/x.js", []byte(min), "js", jsRegexSpec())
	rs := map[string][]string{}
	_ = jsonUnmarshalSym(raw.SymbolsJSON, &rs)
	if len(rs["functions"])+len(rs["consts"]) >= len(sym["functions"])+len(sym["consts"]) {
		t.Fatalf("expected new path to beat raw regex: raw=%v new=%v", rs, sym)
	}
}

func TestExtractJSNonMinifiedUnchanged(t *testing.T) {
	src := "export function foo() {\n  return 1\n}\n\nexport class Bar {\n  m() {}\n}\nconst K = 2\n"
	m, err := extractJS("/y.js", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := regexExtract("/y.js", []byte(src), "js", jsRegexSpec())
	if m.SymbolsJSON != mergeSymbolModules(raw, Module{}).SymbolsJSON {
		t.Fatalf("non-minified path changed: extractJS=%s raw(normalized)=%s", m.SymbolsJSON, raw.SymbolsJSON)
	}
}

func TestExtractJSBasic(t *testing.T) {
	src := []byte(`const fs = require("fs");
import path from "path";
function add(a, b) { return a + b; }
class Box {}
export class ExportedBox {}
const NUM = 42;
`)
	m, err := extractJS("/tmp/x.js", src)
	if err != nil {
		t.Fatalf("extractJS: %v", err)
	}
	if m.Lang != "js" {
		t.Errorf("Lang = %q", m.Lang)
	}
	sym := parseSym(t, m.SymbolsJSON)
	if !strings.Contains(strings.Join(sym["functions"], ","), "add") {
		t.Errorf("functions = %v", sym["functions"])
	}
	if !strings.Contains(strings.Join(sym["types"], ","), "Box") {
		t.Errorf("types = %v", sym["types"])
	}
	if !strings.Contains(strings.Join(sym["types"], ","), "ExportedBox") {
		t.Errorf("types = %v", sym["types"])
	}
	wantImps := map[string]bool{"fs": false, "path": false}
	for _, i := range m.Imports {
		if _, ok := wantImps[i]; ok {
			wantImps[i] = true
		}
	}
	for k, v := range wantImps {
		if !v {
			t.Errorf("missing import %q in %v", k, m.Imports)
		}
	}
}

func TestExtractJSExtensionsRegistered(t *testing.T) {
	for _, ext := range []string{".js", ".jsx", ".mjs", ".cjs"} {
		if _, lang, ok := Lookup(ext); !ok || lang != "js" {
			t.Errorf("%s should map to js, got lang=%q ok=%v", ext, lang, ok)
		}
	}
}
