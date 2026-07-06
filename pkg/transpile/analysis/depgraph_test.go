package analysis

import (
	"path/filepath"
	"testing"
)

// TestBuildConversionUnits_TopoOrder asserts leaf-first ordering.
// Given: a.cpp includes b.h (A depends on B)
// Expect: b.h unit appears before a.cpp unit in the output.
// Covers: ORCH-02, Pitfall 2 (topo sort direction)
func TestBuildConversionUnits_TopoOrder(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "b.h", `#pragma once
void doB();`)
	writeTestFile(t, dir, "a.cpp", `#include "b.h"
void doA() { doB(); }`)

	files := []*SourceFile{
		{Path: filepath.Join(dir, "a.cpp"), RelPath: "a.cpp", Language: "C++ Source"},
		{Path: filepath.Join(dir, "b.h"), RelPath: "b.h", Language: "C/C++ Header"},
	}
	ig := BuildIncludeGraph(files, dir)
	report := &Report{
		Root:         dir,
		TotalFiles:   len(files),
		SourceFiles:  files,
		IncludeGraph: ig,
	}

	units, _, err := BuildConversionUnits(report)
	if err != nil {
		t.Fatalf("BuildConversionUnits error: %v", err)
	}
	if len(units) == 0 {
		t.Fatal("got 0 units, want at least 1")
	}

	// b.h (or its stem unit) must precede a.cpp unit
	bIdx, aIdx := -1, -1
	for i, u := range units {
		for _, f := range u.Files {
			if f == "b.h" {
				bIdx = i
			}
			if f == "a.cpp" {
				aIdx = i
			}
		}
	}
	if bIdx == -1 {
		t.Error("b.h not found in any unit")
	}
	if aIdx == -1 {
		t.Error("a.cpp not found in any unit")
	}
	if bIdx != -1 && aIdx != -1 && bIdx > aIdx {
		t.Errorf("b.h (index %d) must precede a.cpp (index %d) — leaf-first violated", bIdx, aIdx)
	}
}

// TestBuildConversionUnits_SCCCollapse asserts that a cycle is collapsed to one unit.
// Given: a.h includes b.h, b.h includes a.h (mutual cycle = SCC)
// Expect: exactly 1 unit in output, IsSCC=true, Files contains both paths.
// Covers: ORCH-02 (ordering), D-02 (SCC collapse locked)
func TestBuildConversionUnits_SCCCollapse(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "a.h", `#include "b.h"`)
	writeTestFile(t, dir, "b.h", `#include "a.h"`)

	files := []*SourceFile{
		{Path: filepath.Join(dir, "a.h"), RelPath: "a.h", Language: "C/C++ Header"},
		{Path: filepath.Join(dir, "b.h"), RelPath: "b.h", Language: "C/C++ Header"},
	}
	ig := BuildIncludeGraph(files, dir)
	report := &Report{
		Root:         dir,
		TotalFiles:   len(files),
		SourceFiles:  files,
		IncludeGraph: ig,
	}

	units, _, err := BuildConversionUnits(report)
	if err != nil {
		t.Fatalf("BuildConversionUnits error: %v", err)
	}
	if len(units) != 1 {
		t.Fatalf("got %d units, want 1 (SCC must be collapsed)", len(units))
	}
	if !units[0].IsSCC {
		t.Error("collapsed unit must have IsSCC=true")
	}
	if len(units[0].Files) != 2 {
		t.Errorf("collapsed unit must contain 2 files, got %d", len(units[0].Files))
	}
}

// TestSymbolRegistry_ExportedOnly asserts that unexported Python symbols are excluded.
// Given: Python module with class "Foo" (exported) and function "_bar" (unexported)
// Expect: registry.Types["Foo"] present, registry.Functions["_bar"] absent.
// Covers: ORCH-05, D-05 (exported symbols only)
func TestSymbolRegistry_ExportedOnly(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "mod.py", `
class Foo:
    pass

def _bar():
    pass

def PublicFunc():
    pass
`)

	files := []*SourceFile{
		{Path: filepath.Join(dir, "mod.py"), RelPath: "mod.py", Language: "Python Source"},
	}
	report := &Report{
		Root:        dir,
		TotalFiles:  1,
		SourceFiles: files,
	}

	_, registry, err := BuildConversionUnits(report)
	if err != nil {
		t.Fatalf("BuildConversionUnits error: %v", err)
	}
	if registry == nil {
		t.Fatal("registry must not be nil")
	}
	if _, ok := registry.Types["Foo"]; !ok {
		t.Error("registry.Types must contain exported class 'Foo'")
	}
	if _, ok := registry.Functions["_bar"]; ok {
		t.Error("registry.Functions must NOT contain unexported '_bar'")
	}
	if _, ok := registry.Functions["PublicFunc"]; !ok {
		t.Error("registry.Functions must contain exported 'PublicFunc'")
	}
}

// TestBuildConversionUnits_JavaIndependent documents the conservative Java behavior.
// Given: two Java files with no import relationship
// Expect: two independent units, each with IsSCC=false and a single file.
// Covers: ORCH-01 (Java files processed), A1 open question (no JavaImportGraph).
func TestBuildConversionUnits_JavaIndependent(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "Alpha.java", `public class Alpha {}`)
	writeTestFile(t, dir, "Beta.java", `public class Beta {}`)

	files := []*SourceFile{
		{Path: filepath.Join(dir, "Alpha.java"), RelPath: "Alpha.java", Language: "Java Source"},
		{Path: filepath.Join(dir, "Beta.java"), RelPath: "Beta.java", Language: "Java Source"},
	}
	report := &Report{
		Root:        dir,
		TotalFiles:  2,
		SourceFiles: files,
	}

	units, _, err := BuildConversionUnits(report)
	if err != nil {
		t.Fatalf("BuildConversionUnits error: %v", err)
	}
	if len(units) != 2 {
		t.Fatalf("got %d units, want 2 (each Java file is its own unit)", len(units))
	}
	for _, u := range units {
		if u.IsSCC {
			t.Errorf("Java unit %q must not be marked as SCC", u.ID)
		}
		if u.Language != "java" {
			t.Errorf("Java unit %q has language %q, want 'java'", u.ID, u.Language)
		}
	}
}

// TestBuildConversionUnits_NilGraphHandled asserts no panic when graph fields are nil.
// Given: Report with nil IncludeGraph and nil PyImportGraph (user forgot --include-graph)
// Expect: returns empty (non-nil) slice and non-nil registry without panic.
// Covers: Pitfall 5 safety invariant.
func TestBuildConversionUnits_NilGraphHandled(t *testing.T) {
	report := &Report{
		Root:          t.TempDir(),
		TotalFiles:    0,
		SourceFiles:   nil,
		IncludeGraph:  nil,
		PyImportGraph: nil,
	}
	units, registry, err := BuildConversionUnits(report)
	if err != nil {
		t.Fatalf("must not error on empty report: %v", err)
	}
	if units == nil {
		t.Error("units slice must not be nil (use []ConversionUnit{})")
	}
	if registry == nil {
		t.Error("registry must not be nil")
	}
}

// TestIsWithinRoot asserts the path-traversal guard enforces a
// separator boundary so a sibling directory sharing a name prefix is
// rejected (CR-01, T-03-01).
func TestIsWithinRoot(t *testing.T) {
	sep := string(filepath.Separator)
	root := filepath.Clean("/proj/src")
	tests := []struct {
		name     string
		resolved string
		want     bool
	}{
		{"root itself", root, true},
		{"true subpath", filepath.Clean("/proj/src/foo/bar.h"), true},
		{"sibling prefix attacker", filepath.Clean("/proj/src-evil/secret.h"), false},
		{"parent escape", filepath.Clean("/proj/other.h"), false},
		{"prefix no separator", filepath.Clean("/proj/srcfoo"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsWithinRoot(root, tt.resolved); got != tt.want {
				t.Errorf("IsWithinRoot(%q, %q) = %v, want %v (sep=%q)",
					root, tt.resolved, got, tt.want, sep)
			}
		})
	}
}

// TestBuildConversionUnits_DiamondTopoOrder locks the edge-orientation
// and reversal contract with a multi-level diamond: A→B, A→C, B→D, C→D.
// Expect D before B and C; B and C before A (WR-03).
func TestBuildConversionUnits_DiamondTopoOrder(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "d.h", `#pragma once
void doD();`)
	writeTestFile(t, dir, "b.h", `#pragma once
#include "d.h"
void doB();`)
	writeTestFile(t, dir, "c.h", `#pragma once
#include "d.h"
void doC();`)
	writeTestFile(t, dir, "a.cpp", `#include "b.h"
#include "c.h"
void doA() { doB(); doC(); }`)

	files := []*SourceFile{
		{Path: filepath.Join(dir, "a.cpp"), RelPath: "a.cpp", Language: "C++ Source"},
		{Path: filepath.Join(dir, "b.h"), RelPath: "b.h", Language: "C/C++ Header"},
		{Path: filepath.Join(dir, "c.h"), RelPath: "c.h", Language: "C/C++ Header"},
		{Path: filepath.Join(dir, "d.h"), RelPath: "d.h", Language: "C/C++ Header"},
	}
	ig := BuildIncludeGraph(files, dir)
	report := &Report{
		Root:         dir,
		TotalFiles:   len(files),
		SourceFiles:  files,
		IncludeGraph: ig,
	}

	units, _, err := BuildConversionUnits(report)
	if err != nil {
		t.Fatalf("BuildConversionUnits error: %v", err)
	}

	idx := map[string]int{}
	for i, u := range units {
		for _, f := range u.Files {
			idx[f] = i
		}
	}
	for _, f := range []string{"a.cpp", "b.h", "c.h", "d.h"} {
		if _, ok := idx[f]; !ok {
			t.Fatalf("%s not found in any unit", f)
		}
	}
	if idx["d.h"] > idx["b.h"] || idx["d.h"] > idx["c.h"] {
		t.Errorf("d.h must precede b.h and c.h: d=%d b=%d c=%d",
			idx["d.h"], idx["b.h"], idx["c.h"])
	}
	if idx["b.h"] > idx["a.cpp"] || idx["c.h"] > idx["a.cpp"] {
		t.Errorf("b.h and c.h must precede a.cpp: b=%d c=%d a=%d",
			idx["b.h"], idx["c.h"], idx["a.cpp"])
	}
}

// TestSymbolRegistry_PythonUnitIDNonEmpty asserts Python symbols get a
// non-empty UnitID (WR-02 regression: fallback keyed on absolute path
// always missed and emitted UnitID == "").
func TestSymbolRegistry_PythonUnitIDNonEmpty(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "mod.py", `
class Widget:
    pass

def Build():
    pass
`)
	files := []*SourceFile{
		{Path: filepath.Join(dir, "mod.py"), RelPath: "mod.py", Language: "Python Source"},
	}
	report := &Report{
		Root:        dir,
		TotalFiles:  1,
		SourceFiles: files,
	}

	_, registry, err := BuildConversionUnits(report)
	if err != nil {
		t.Fatalf("BuildConversionUnits error: %v", err)
	}
	if e, ok := registry.Types["Widget"]; !ok {
		t.Fatal("registry.Types must contain 'Widget'")
	} else if e.UnitID == "" {
		t.Error("Python class 'Widget' has empty UnitID — orchestrator linkage broken")
	}
	if e, ok := registry.Functions["Build"]; !ok {
		t.Fatal("registry.Functions must contain 'Build'")
	} else if e.UnitID == "" {
		t.Error("Python func 'Build' has empty UnitID — orchestrator linkage broken")
	}
}
