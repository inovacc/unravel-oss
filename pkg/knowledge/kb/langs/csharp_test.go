package langs

import (
	"strings"
	"testing"
)

func TestExtractCSharpBasic(t *testing.T) {
	src := []byte(`using System;
using System.Collections.Generic;
using static System.Math;

namespace Foo {
    public class Bar {
        public int Add(int a, int b) { return a + b; }
        private static void Helper() {}
    }

    public interface IDriver {
        void Drive();
    }

    public enum Color { Red, Green }
    public record Point(int X, int Y);
}
`)
	m, err := extractCS("/tmp/foo.cs", src)
	if err != nil {
		t.Fatalf("extractCS: %v", err)
	}
	if m.Lang != "csharp" {
		t.Errorf("Lang = %q", m.Lang)
	}
	sym := parseSym(t, m.SymbolsJSON)
	tgot := strings.Join(sym["types"], ",")
	for _, want := range []string{"Bar", "IDriver", "Color", "Point"} {
		if !strings.Contains(tgot, want) {
			t.Errorf("types missing %q: %v", want, sym["types"])
		}
	}
	fgot := strings.Join(sym["functions"], ",")
	if !strings.Contains(fgot, "Add") {
		t.Errorf("functions = %v", sym["functions"])
	}
	imps := strings.Join(m.Imports, ",")
	for _, want := range []string{"System", "System.Collections.Generic", "System.Math"} {
		if !strings.Contains(imps, want) {
			t.Errorf("imports missing %q: %v", want, m.Imports)
		}
	}
}

func TestExtractCSExtensionRegistered(t *testing.T) {
	if _, lang, ok := Lookup(".cs"); !ok || lang != "csharp" {
		t.Errorf(".cs lang=%q ok=%v", lang, ok)
	}
}
