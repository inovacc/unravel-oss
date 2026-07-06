package langs

import (
	"encoding/json"
	"strings"
	"testing"
)

func parseSym(t *testing.T, s string) map[string][]string {
	t.Helper()
	if s == "" {
		return map[string][]string{}
	}
	out := map[string][]string{}
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		t.Fatalf("symbols json: %v", err)
	}
	return out
}

func TestExtractTSFunctionsAndClasses(t *testing.T) {
	src := []byte(`import { foo } from "bar";
import "side";
export function Hello(): string { return "hi"; }
async function helper() {}
export class Widget { name: string = ""; }
interface Drivable { drive(): void; }
type ID = string;
const PI = 3.14;
`)
	m, err := extractTS("/tmp/foo.ts", src)
	if err != nil {
		t.Fatalf("extractTS: %v", err)
	}
	if m.Lang != "ts" {
		t.Errorf("Lang = %q", m.Lang)
	}
	sym := parseSym(t, m.SymbolsJSON)
	if !strings.Contains(strings.Join(sym["functions"], ","), "Hello") {
		t.Errorf("functions = %v", sym["functions"])
	}
	if !strings.Contains(strings.Join(sym["functions"], ","), "helper") {
		t.Errorf("functions = %v", sym["functions"])
	}
	if !strings.Contains(strings.Join(sym["types"], ","), "Widget") {
		t.Errorf("types = %v", sym["types"])
	}
	if !strings.Contains(strings.Join(sym["types"], ","), "Drivable") {
		t.Errorf("types = %v", sym["types"])
	}
	if !strings.Contains(strings.Join(sym["consts"], ","), "PI") {
		t.Errorf("consts = %v", sym["consts"])
	}
	wantImps := map[string]bool{"bar": false, "side": false}
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

func TestExtractTSTSXRegistered(t *testing.T) {
	if _, lang, ok := Lookup(".tsx"); !ok || lang != "ts" {
		t.Errorf(".tsx should map to ts, got lang=%q ok=%v", lang, ok)
	}
}

func TestExtractTSEmptyFile(t *testing.T) {
	m, err := extractTS("/tmp/empty.ts", []byte(""))
	if err != nil {
		t.Fatalf("extractTS empty: %v", err)
	}
	if m.Size != 0 {
		t.Errorf("Size = %d", m.Size)
	}
	if m.Lang != "ts" {
		t.Errorf("Lang = %q", m.Lang)
	}
	if len(m.BodySHA256) != 64 {
		t.Errorf("sha256 len = %d", len(m.BodySHA256))
	}
}

func TestExtractTSRequireFallback(t *testing.T) {
	src := []byte(`const x = require("./local");
const y = require("pkg");`)
	m, _ := extractTS("/tmp/r.ts", src)
	got := strings.Join(m.Imports, ",")
	if !strings.Contains(got, "./local") || !strings.Contains(got, "pkg") {
		t.Errorf("imports = %v", m.Imports)
	}
}
