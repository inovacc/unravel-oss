package langs

import (
	"strings"
	"testing"
)

func TestExtractJavaBasic(t *testing.T) {
	src := []byte(`package com.example;

import java.util.List;
import java.util.Map;
import static java.util.Collections.emptyList;

public class Greeter {
    public String hello(String name) {
        return "Hi " + name;
    }
    private static int helper() { return 0; }
}

interface Drivable {
    void drive();
}

enum Color { RED, GREEN }
`)
	m, err := extractJava("/tmp/Greeter.java", src)
	if err != nil {
		t.Fatalf("extractJava: %v", err)
	}
	if m.Lang != "java" {
		t.Errorf("Lang = %q", m.Lang)
	}
	sym := parseSym(t, m.SymbolsJSON)
	tgot := strings.Join(sym["types"], ",")
	for _, want := range []string{"Greeter", "Drivable", "Color"} {
		if !strings.Contains(tgot, want) {
			t.Errorf("types missing %q: %v", want, sym["types"])
		}
	}
	fgot := strings.Join(sym["functions"], ",")
	if !strings.Contains(fgot, "hello") {
		t.Errorf("functions missing hello: %v", sym["functions"])
	}
	imps := strings.Join(m.Imports, ",")
	for _, want := range []string{"java.util.List", "java.util.Map", "java.util.Collections.emptyList"} {
		if !strings.Contains(imps, want) {
			t.Errorf("imports missing %q: %v", want, m.Imports)
		}
	}
}

func TestExtractJavaExtensionRegistered(t *testing.T) {
	if _, lang, ok := Lookup(".java"); !ok || lang != "java" {
		t.Errorf(".java lang=%q ok=%v", lang, ok)
	}
}
