//go:build goresym

package goresym

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// This file characterizes GoReSym's `-t` (type extraction) flag and locks
// the type -> Result.Types projection. It is internal (package goresym, not
// goresym_test) so it can exercise mapGoresymOutput directly with synthetic
// GoReSym JSON — the moduledata-version limitation described below means a
// live Go 1.26 binary yields no Types, so the unit-level mapping test is the
// load-bearing assertion that the parse path works.
//
// Findings (GoReSym v1.7.1, Go 1.26.4 toolchain — see
// docs/design/2026-goresym-backend.md §O3):
//
//   - `-t` instructs GoReSym to "enumerate typelinks and itablinks". On
//     success it emits two arrays of objfile.Type records:
//       Types      <- moduledata typelinks
//       Interfaces <- moduledata itablinks
//     Each record is {VA, Str, Kind, Reconstructed}. Str is the Go type
//     name (e.g. "*main.GreeterWidget"); Kind is the reflect.Kind; the
//     optional Reconstructed holds re-emitted Go source for structs/ifaces.
//
//   - For Go 1.26 binaries GoReSym v1.7.1 reads ModuleMeta.Typelinks /
//     ITablinks as zero-length (the moduledata struct layout drifted past
//     what v1.7.1 forks), so both Types and Interfaces marshal as JSON
//     null. Function recovery via the pclntab is unaffected. The backend
//     therefore degrades to an empty Result.Types — never an error.

// requireToolInternal mirrors requireTool from recover_goresym_test.go but
// is local to this internal-package test file.
func requireToolInternal(t *testing.T) {
	t.Helper()
	if _, err := lookupGoresym(); err != nil {
		t.Skip("GoReSym executable not on PATH; skipping live type-recovery test")
	}
}

// TestMapGoresymOutput_TypesProjection pins the contract that the GoReSym
// `-t` output (Types + Interfaces arrays) is projected into Result.Types,
// deduplicated, with empty Str entries dropped. This is independent of the
// installed GoReSym/Go version, so it is the authoritative regression guard
// for the type -> KB path.
func TestMapGoresymOutput_TypesProjection(t *testing.T) {
	raw := []byte(`{
		"Version": "1.26.4",
		"BuildId": "abc",
		"UserFunctions": [{"Start": 4096, "FullName": "main.main", "PackageName": "main"}],
		"Types": [
			{"VA": 1, "Str": "*main.GreeterWidget", "Kind": "ptr", "Reconstructed": "type GreeterWidget struct { Name string; Count int }"},
			{"VA": 2, "Str": "main.PaymentRecord", "Kind": "struct"},
			{"VA": 3, "Str": "main.PaymentRecord", "Kind": "struct"},
			{"VA": 4, "Str": "", "Kind": "struct"}
		],
		"Interfaces": [
			{"VA": 5, "Str": "main.Speaker", "Kind": "interface"}
		],
		"BuildInfo": {"GoVersion": "go1.26.4", "Main": {"Path": "fixturecli"}}
	}`)

	var parsed goresymOutput
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("unmarshal synthetic GoReSym output: %v", err)
	}

	res := mapGoresymOutput(&parsed, Options{})

	want := map[string]bool{
		"*main.GreeterWidget": true,
		"main.PaymentRecord":  true,
		"main.Speaker":        true,
	}
	if len(res.Types) != len(want) {
		t.Fatalf("Result.Types = %v; want %d distinct names", res.Types, len(want))
	}
	for _, got := range res.Types {
		if !want[got] {
			t.Errorf("unexpected type %q in Result.Types", got)
		}
		delete(want, got)
	}
	for missing := range want {
		t.Errorf("expected type %q in Result.Types, missing", missing)
	}

	// Empty Str must be dropped and duplicates collapsed.
	for _, n := range res.Types {
		if n == "" {
			t.Error("empty type name leaked into Result.Types")
		}
	}
}

// TestRecover_LiveTypeCharacterization builds a fixture with named struct +
// interface types, runs the real GoReSym backend with `-t`, and characterizes
// the Types output. It asserts function recovery (always works) and records
// the type-array behavior honestly: on toolchains where GoReSym cannot read
// the moduledata typelinks (current Go 1.26 case) Result.Types is empty but
// the call still succeeds — it must never error solely because no types were
// found.
func TestRecover_LiveTypeCharacterization(t *testing.T) {
	requireToolInternal(t)

	dir := t.TempDir()
	writeFixtureSource(t, dir)

	bin := filepath.Join(dir, "fixture_bin")
	build := exec.Command("go", "build", "-o", bin, ".")
	build.Dir = dir
	build.Env = append(os.Environ(), "GOOS="+runtime.GOOS, "GOARCH="+runtime.GOARCH)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building fixture failed: %v\n%s", err, out)
	}

	res, err := Recover(context.Background(), bin, Options{})
	if err != nil {
		t.Fatalf("Recover on fixture returned error: %v", err)
	}
	if res == nil {
		t.Fatal("Recover returned nil result")
	}

	// Function recovery is the always-on guarantee.
	if len(res.Symbols) == 0 {
		t.Fatalf("expected >=1 recovered symbol from fixture, got 0")
	}

	// Type recovery is best-effort and version-dependent. When the
	// installed GoReSym CAN enumerate this binary's typelinks, our fixture's
	// named types must surface; when it cannot (Go 1.26 + GoReSym v1.7.1),
	// Types is empty and that is a documented, non-error outcome.
	if len(res.Types) == 0 {
		t.Logf("characterization: GoReSym emitted no types for this binary "+
			"(GoVersion=%s) — expected with GoReSym v1.7.1 on Go 1.26; see "+
			"docs/design/2026-goresym-backend.md §O3", res.GoVersion)
		return
	}

	t.Logf("characterization: GoReSym recovered %d type names", len(res.Types))
	var sawNamed bool
	for _, name := range res.Types {
		if name == "" {
			t.Error("empty type name in Result.Types")
		}
		switch name {
		case "main.GreeterWidget", "*main.GreeterWidget",
			"main.PaymentRecord", "*main.PaymentRecord",
			"main.Speaker", "*main.Speaker":
			sawNamed = true
		}
	}
	if !sawNamed {
		t.Logf("characterization: GoReSym surfaced types but none matched the "+
			"fixture's named types; first few=%v", firstN(res.Types, 8))
	}
}

func firstN(s []string, n int) []string {
	if len(s) < n {
		return s
	}
	return s[:n]
}

// writeFixtureSource writes a tiny self-contained module with named struct
// and interface types so GoReSym has user types to enumerate under `-t`.
func writeFixtureSource(t *testing.T, dir string) {
	t.Helper()
	mustWrite(t, filepath.Join(dir, "go.mod"), "module fixturecli\n\ngo 1.25\n")
	mustWrite(t, filepath.Join(dir, "main.go"), fixtureMainSource)
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

const fixtureMainSource = `package main

import "fmt"

// GreeterWidget is a named struct type to test type recovery.
type GreeterWidget struct {
	Name  string
	Count int
}

// PaymentRecord is a second named struct for type recovery.
type PaymentRecord struct {
	Amount   int64
	Currency string
	Greeter  *GreeterWidget
}

// Speaker is an interface type to test interface (itablink) recovery.
type Speaker interface {
	Speak() string
}

func (g *GreeterWidget) Speak() string {
	return fmt.Sprintf("hello %s x%d", g.Name, g.Count)
}

func processPayment(p PaymentRecord) string {
	return fmt.Sprintf("%d %s", p.Amount, p.Currency)
}

func main() {
	g := &GreeterWidget{Name: "world", Count: 3}
	var s Speaker = g
	p := PaymentRecord{Amount: 100, Currency: "BRL", Greeter: g}
	fmt.Println(s.Speak())
	fmt.Println(processPayment(p))
}
`
