package writer

import (
	"strings"

	"github.com/inovacc/unravel-oss/pkg/java/decompiler/types"
)

// TypeWriter renders Java type names for source output.
type TypeWriter struct {
	imports *ImportTracker
}

// NewTypeWriter creates a type writer with an import tracker.
func NewTypeWriter(imports *ImportTracker) *TypeWriter {
	return &TypeWriter{imports: imports}
}

// RenderType converts a JavaType to its source-level representation.
// If an import tracker is provided, it registers imports and returns
// the simple name; otherwise returns the fully-qualified name.
func (tw *TypeWriter) RenderType(t types.JavaType) string {
	if t == nil {
		return "void"
	}

	// Handle array types
	if t.IsArray() {
		elem := t.ElementType()
		dims := t.ArrayDimensions()
		base := tw.RenderType(elem)

		return base + strings.Repeat("[]", dims)
	}

	// Primitives use their direct names
	if t.IsPrimitive() {
		return t.Name()
	}

	name := t.Name()

	// void
	if name == "void" {
		return "void"
	}

	// Check raw name for FQN to register imports
	rawName := t.RawName()
	if rawName != "" && strings.Contains(rawName, ".") && tw.imports != nil {
		tw.imports.Add(rawName)
	}

	return name
}

// RenderMethodType renders a method signature type string.
func (tw *TypeWriter) RenderMethodType(returnType types.JavaType, paramTypes []types.JavaType) string {
	var b strings.Builder
	b.WriteString(tw.RenderType(returnType))
	b.WriteByte('(')

	for i, pt := range paramTypes {
		if i > 0 {
			b.WriteString(", ")
		}

		b.WriteString(tw.RenderType(pt))
	}

	b.WriteByte(')')

	return b.String()
}
