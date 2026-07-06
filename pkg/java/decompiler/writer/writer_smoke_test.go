/*
Copyright (c) 2026 Security Research
*/
package writer

import (
	"strings"
	"testing"

	"github.com/inovacc/unravel-oss/pkg/java/decompiler/types"
)

func TestNewJavaWriter(t *testing.T) {
	w := New()
	if w == nil {
		t.Fatal("New returned nil")
	}
}

func TestNewImportTracker(t *testing.T) {
	it := NewImportTracker()
	if it == nil {
		t.Fatal("NewImportTracker returned nil")
	}
}

func TestNewTypeWriter(t *testing.T) {
	it := NewImportTracker()
	tw := NewTypeWriter(it)
	if tw == nil {
		t.Fatal("NewTypeWriter returned nil")
	}
}

func TestImportTracker_WritesNestedClassImports(t *testing.T) {
	it := NewImportTracker()
	it.Add("java.lang.invoke.MethodHandles$Lookup")

	got := it.WriteImports()
	want := "import java.lang.invoke.MethodHandles.Lookup;\n"

	if got != want {
		t.Fatalf("WriteImports()=%q want %q", got, want)
	}
	if !strings.Contains(got, "MethodHandles.Lookup") {
		t.Fatalf("WriteImports() did not normalize nested class separator: %q", got)
	}
}

func TestTypeWriter_RenderNestedClassType(t *testing.T) {
	it := NewImportTracker()
	tw := NewTypeWriter(it)

	got := tw.RenderType(types.NewRefType("java.lang.invoke.MethodHandles$Lookup"))
	if got != "Lookup" {
		t.Fatalf("RenderType()=%q want Lookup", got)
	}

	imports := it.WriteImports()
	if !strings.Contains(imports, "java.lang.invoke.MethodHandles.Lookup") {
		t.Fatalf("imports did not normalize nested class name: %q", imports)
	}
}
