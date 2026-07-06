package langs

import (
	"strings"
	"testing"
)

func TestExtractCFunctionsAndTypes(t *testing.T) {
	src := []byte(`#include <stdio.h>
#include "local.h"
#define MAX_LEN 256

struct Point { int x; int y; };
typedef enum Color { RED, GREEN } Color;

int add(int a, int b) {
    return a + b;
}

static void noop(void) {
}
`)
	m, err := extractC("/tmp/foo.c", src)
	if err != nil {
		t.Fatalf("extractC: %v", err)
	}
	if m.Lang != "c" {
		t.Errorf("Lang = %q", m.Lang)
	}
	sym := parseSym(t, m.SymbolsJSON)
	got := strings.Join(sym["functions"], ",")
	if !strings.Contains(got, "add") {
		t.Errorf("functions = %v", sym["functions"])
	}
	tgot := strings.Join(sym["types"], ",")
	if !strings.Contains(tgot, "Point") {
		t.Errorf("types = %v", sym["types"])
	}
	imps := strings.Join(m.Imports, ",")
	if !strings.Contains(imps, "stdio.h") || !strings.Contains(imps, "local.h") {
		t.Errorf("imports = %v", m.Imports)
	}
	if !strings.Contains(strings.Join(sym["consts"], ","), "MAX_LEN") {
		t.Errorf("consts (defines) = %v", sym["consts"])
	}
}

func TestExtractCPPClasses(t *testing.T) {
	src := []byte(`#include <vector>

class Widget {
public:
    Widget() {}
};

struct Pair { int a; int b; };
`)
	m, err := extractCPP("/tmp/foo.cpp", src)
	if err != nil {
		t.Fatalf("extractCPP: %v", err)
	}
	if m.Lang != "cpp" {
		t.Errorf("Lang = %q", m.Lang)
	}
	sym := parseSym(t, m.SymbolsJSON)
	tgot := strings.Join(sym["types"], ",")
	if !strings.Contains(tgot, "Widget") || !strings.Contains(tgot, "Pair") {
		t.Errorf("types = %v", sym["types"])
	}
}

func TestExtractCExtensionsRegistered(t *testing.T) {
	for _, ext := range []string{".c", ".h"} {
		if _, lang, ok := Lookup(ext); !ok || lang != "c" {
			t.Errorf("%s lang=%q ok=%v", ext, lang, ok)
		}
	}
	for _, ext := range []string{".cpp", ".hpp", ".cc", ".cxx"} {
		if _, lang, ok := Lookup(ext); !ok || lang != "cpp" {
			t.Errorf("%s lang=%q ok=%v", ext, lang, ok)
		}
	}
}
