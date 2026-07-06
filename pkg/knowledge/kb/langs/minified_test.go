package langs

import "testing"

func TestLooksMinified(t *testing.T) {
	long := "function a(){return 1};"
	for len(long) < 5000 {
		long += "var x=1;y=2;z=function(){};"
	}
	if !looksMinified([]byte(long)) {
		t.Fatal("single huge line must be detected minified")
	}
	normal := "function a() {\n  return 1\n}\n\nclass B {\n  m() {}\n}\n"
	if looksMinified([]byte(normal)) {
		t.Fatal("normal multi-line JS must NOT be minified")
	}
	if looksMinified([]byte("")) || looksMinified([]byte("var x=1\n")) {
		t.Fatal("tiny/empty must not be minified")
	}
}

func TestMergeSymbolModules(t *testing.T) {
	a := Module{SymbolsJSON: `{"functions":["Aa"],"imports":["m"]}`}
	b := Module{SymbolsJSON: `{"functions":["Aa","Bb"],"types":["C"],"imports":["m","n"]}`}
	got := mergeSymbolModules(a, b)
	sym := map[string][]string{}
	mustUnmarshalSym(t, got.SymbolsJSON, &sym)
	if !eqSet(sym["functions"], []string{"Aa", "Bb"}) {
		t.Fatalf("functions union = %v", sym["functions"])
	}
	if !eqSet(sym["types"], []string{"C"}) {
		t.Fatalf("types union = %v", sym["types"])
	}
	if !eqSet(sym["imports"], []string{"m", "n"}) {
		t.Fatalf("imports union = %v", sym["imports"])
	}
	// deterministic: re-run identical
	if mergeSymbolModules(a, b).SymbolsJSON != got.SymbolsJSON {
		t.Fatal("merge not deterministic")
	}
}

// test helpers (local)
func mustUnmarshalSym(t *testing.T, s string, v any) {
	t.Helper()
	if err := jsonUnmarshalSym(s, v); err != nil {
		t.Fatalf("unmarshal %q: %v", s, err)
	}
}
func eqSet(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	m := map[string]bool{}
	for _, g := range got {
		m[g] = true
	}
	for _, w := range want {
		if !m[w] {
			return false
		}
	}
	return true
}
