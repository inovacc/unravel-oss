package patterns

import (
	"strings"

	"github.com/inovacc/unravel-oss/pkg/java/decompiler/ast"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/types"
)

// simplifyStringConcat detects StringBuilder append chains converted to
// toString() and simplifies them into binary "+" concatenation expressions.
//
// Pattern:
//
//	new StringBuilder().append(a).append(b).toString()
//	  -> a + b
//
// Also handles the variant where the StringBuilder constructor takes an
// initial string argument:
//
//	new StringBuilder("prefix").append(x).toString()
//	  -> "prefix" + x
func simplifyStringConcat(e ast.Expression) (ast.Expression, bool) {
	// Must be a method invocation of toString()
	invoke, ok := e.(*ast.MethodInvocation)
	if !ok {
		return nil, false
	}

	if invoke.Method.MethodName != "toString" || len(invoke.Args) != 0 {
		return nil, false
	}

	// The receiver must be an append chain rooted at a StringBuilder constructor
	parts, ok := collectAppendChain(invoke.Object)
	if !ok || len(parts) == 0 {
		return nil, false
	}

	// Build a left-associative binary "+" tree from collected parts
	result := parts[0]
	for i := 1; i < len(parts); i++ {
		result = ast.NewArithmeticOperation(ast.OpAdd, result, parts[i], types.StringType)
	}

	return result, true
}

// collectAppendChain walks backwards through a chain of .append() calls
// on a StringBuilder, collecting the appended values in order.
// Returns (values, true) if a valid StringBuilder chain was found.
func collectAppendChain(e ast.Expression) ([]ast.Expression, bool) {
	if e == nil {
		return nil, false
	}

	switch v := e.(type) {
	case *ast.MethodInvocation:
		// Check for .append(arg) call
		if v.Method.MethodName == "append" && len(v.Args) == 1 {
			// Recurse on the receiver to collect earlier parts
			earlier, ok := collectAppendChain(v.Object)
			if !ok {
				return nil, false
			}
			return append(earlier, v.Args[0]), true
		}

		// Check for new StringBuilder() or new StringBuilder(initialValue)
		// This appears as invokespecial <init> on a StringBuilder
		if isStringBuilderInit(v) {
			if len(v.Args) == 0 {
				return nil, true // empty init, no initial values
			}
			if len(v.Args) == 1 {
				// StringBuilder(String) constructor -- the arg is the first part
				return []ast.Expression{v.Args[0]}, true
			}
			// StringBuilder(int) capacity constructor -- no initial value
			if len(v.Args) == 1 && isIntType(v.Args[0]) {
				return nil, true
			}
		}

	case *ast.NewObject:
		// Bare "new StringBuilder" without <init> merged
		if isStringBuilderType(v.ClassType) {
			return nil, true
		}
	}

	return nil, false
}

// isStringBuilderInit returns true if the invocation is a StringBuilder constructor call.
func isStringBuilderInit(inv *ast.MethodInvocation) bool {
	if inv.Kind != ast.InvokeSpecial {
		return false
	}

	if inv.Method.MethodName != "<init>" {
		return false
	}

	return isStringBuilderClassName(inv.Method.ClassName)
}

// isStringBuilderClassName checks if a class name refers to StringBuilder or StringBuffer.
func isStringBuilderClassName(name string) bool {
	simple := simpleName(name)
	return simple == "StringBuilder" || simple == "StringBuffer"
}

// isStringBuilderType checks if a JavaType refers to StringBuilder or StringBuffer.
func isStringBuilderType(t types.JavaType) bool {
	if t == nil {
		return false
	}

	return isStringBuilderClassName(t.String())
}

// isIntType returns true if the expression has an int-like type.
func isIntType(e ast.Expression) bool {
	t := e.Type()
	return t == types.TypeInt || t == types.TypeByte || t == types.TypeShort
}

// simpleName extracts the simple class name from a possibly qualified name.
// "java.lang.StringBuilder" -> "StringBuilder", "java/lang/StringBuilder" -> "StringBuilder".
func simpleName(name string) string {
	if idx := strings.LastIndexByte(name, '.'); idx >= 0 {
		return name[idx+1:]
	}

	if idx := strings.LastIndexByte(name, '/'); idx >= 0 {
		return name[idx+1:]
	}

	return name
}
