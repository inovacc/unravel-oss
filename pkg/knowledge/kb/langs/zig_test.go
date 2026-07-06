package langs

import (
	"strings"
	"testing"
)

func TestExtractZigBasic(t *testing.T) {
	src := []byte(`const std = @import("std");
const builtin = @import("builtin");
const c = @cImport({});

pub fn add(a: i32, b: i32) i32 {
    return a + b;
}

fn helper() void {}

pub const Point = struct {
    x: i32,
    y: i32,
};

const Color = enum { red, green };
`)
	m, err := extractZig("/tmp/foo.zig", src)
	if err != nil {
		t.Fatalf("extractZig: %v", err)
	}
	if m.Lang != "zig" {
		t.Errorf("Lang = %q", m.Lang)
	}
	sym := parseSym(t, m.SymbolsJSON)
	fgot := strings.Join(sym["functions"], ",")
	if !strings.Contains(fgot, "add") || !strings.Contains(fgot, "helper") {
		t.Errorf("functions = %v", sym["functions"])
	}
	tgot := strings.Join(sym["types"], ",")
	if !strings.Contains(tgot, "Point") || !strings.Contains(tgot, "Color") {
		t.Errorf("types = %v", sym["types"])
	}
	imps := strings.Join(m.Imports, ",")
	for _, want := range []string{"std", "builtin", "@cImport"} {
		if !strings.Contains(imps, want) {
			t.Errorf("imports missing %q: %v", want, m.Imports)
		}
	}
}

func TestExtractZigExtensionRegistered(t *testing.T) {
	if _, lang, ok := Lookup(".zig"); !ok || lang != "zig" {
		t.Errorf(".zig lang=%q ok=%v", lang, ok)
	}
}
