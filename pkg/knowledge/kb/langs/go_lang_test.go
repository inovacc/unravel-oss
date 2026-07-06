package langs

import (
	"encoding/json"
	"strings"
	"testing"
)

// containsAll asserts that every want string is in got, where got was
// pulled out of the SymbolsJSON for one bucket.
func containsAll(got []string, want ...string) bool {
	set := make(map[string]struct{}, len(got))
	for _, g := range got {
		set[g] = struct{}{}
	}
	for _, w := range want {
		if _, ok := set[w]; !ok {
			return false
		}
	}
	return true
}

func TestExtractGoSimpleFunc(t *testing.T) {
	src := []byte(`package foo

func Hello() string { return "hi" }
func helper() {}`)
	m, err := extractGo("/tmp/foo.go", src)
	if err != nil {
		t.Fatalf("extractGo: %v", err)
	}
	if m.Lang != "go" {
		t.Errorf("Lang = %q, want go", m.Lang)
	}
	if !strings.HasPrefix(m.Name, "foo.") {
		t.Errorf("Name should start with package name, got %q", m.Name)
	}
	var sym map[string][]string
	if err := json.Unmarshal([]byte(m.SymbolsJSON), &sym); err != nil {
		t.Fatalf("symbols JSON: %v", err)
	}
	if !containsAll(sym["functions"], "Hello", "helper") {
		t.Errorf("functions = %v, want Hello + helper", sym["functions"])
	}
}

func TestExtractGoStructAndInterface(t *testing.T) {
	src := []byte(`package bar

type Widget struct{ Name string }
type Driver interface{ Drive() error }`)
	m, err := extractGo("/tmp/bar.go", src)
	if err != nil {
		t.Fatalf("extractGo: %v", err)
	}
	var sym map[string][]string
	_ = json.Unmarshal([]byte(m.SymbolsJSON), &sym)
	if !containsAll(sym["types"], "Widget", "Driver") {
		t.Errorf("types = %v", sym["types"])
	}
}

func TestExtractGoConstAndVar(t *testing.T) {
	src := []byte(`package baz

const Pi = 3.14
var Counter int`)
	m, err := extractGo("/tmp/baz.go", src)
	if err != nil {
		t.Fatalf("extractGo: %v", err)
	}
	var sym map[string][]string
	_ = json.Unmarshal([]byte(m.SymbolsJSON), &sym)
	if !containsAll(sym["consts"], "Pi") {
		t.Errorf("consts = %v", sym["consts"])
	}
	if !containsAll(sym["vars"], "Counter") {
		t.Errorf("vars = %v", sym["vars"])
	}
}

func TestExtractGoImports(t *testing.T) {
	src := []byte(`package qux

import (
	"fmt"
	"strings"
	other "path/filepath"
)

func _() { fmt.Println(strings.ToLower("X")); _ = other.Base("/a/b") }`)
	m, err := extractGo("/tmp/qux.go", src)
	if err != nil {
		t.Fatalf("extractGo: %v", err)
	}
	if !containsAll(m.Imports, "fmt", "strings", "path/filepath") {
		t.Errorf("imports = %v", m.Imports)
	}
}

func TestExtractGoBadSyntaxReturnsError(t *testing.T) {
	src := []byte(`package broken

func {{{ totally not Go`)
	_, err := extractGo("/tmp/broken.go", src)
	if err == nil {
		t.Error("expected parse error for malformed Go file")
	}
}

func TestExtractGoSHA256IsDeterministic(t *testing.T) {
	src := []byte(`package z
func A() {}
`)
	m1, _ := extractGo("/tmp/a.go", src)
	m2, _ := extractGo("/tmp/a.go", src)
	if m1.BodySHA256 != m2.BodySHA256 {
		t.Error("sha256 should be deterministic for same body")
	}
	if len(m1.BodySHA256) != 64 {
		t.Errorf("sha256 hex length = %d, want 64", len(m1.BodySHA256))
	}
}
