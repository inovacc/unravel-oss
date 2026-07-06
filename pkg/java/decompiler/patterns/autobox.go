package patterns

import (
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/ast"
)

// Wrapper class valueOf methods (boxing) and primitive extraction methods (unboxing).
var (
	// boxingMethods maps "ClassName.methodName" to true for recognized boxing calls.
	// These are INVOKESTATIC calls: Integer.valueOf(int) -> Integer, etc.
	boxingMethods = map[string]bool{
		"java.lang.Integer.valueOf":   true,
		"java.lang.Long.valueOf":      true,
		"java.lang.Float.valueOf":     true,
		"java.lang.Double.valueOf":    true,
		"java.lang.Boolean.valueOf":   true,
		"java.lang.Byte.valueOf":      true,
		"java.lang.Short.valueOf":     true,
		"java.lang.Character.valueOf": true,
		// Also match internal names (with slashes)
		"java/lang/Integer.valueOf":   true,
		"java/lang/Long.valueOf":      true,
		"java/lang/Float.valueOf":     true,
		"java/lang/Double.valueOf":    true,
		"java/lang/Boolean.valueOf":   true,
		"java/lang/Byte.valueOf":      true,
		"java/lang/Short.valueOf":     true,
		"java/lang/Character.valueOf": true,
	}

	// unboxingMethods lists the INVOKEVIRTUAL method names that extract
	// primitives from wrapper types: x.intValue() -> int, etc.
	unboxingMethods = map[string]bool{
		"intValue":     true,
		"longValue":    true,
		"floatValue":   true,
		"doubleValue":  true,
		"booleanValue": true,
		"byteValue":    true,
		"shortValue":   true,
		"charValue":    true,
	}
)

// simplifyAutobox detects compiler-generated boxing and unboxing calls
// and replaces them with the underlying value.
//
// Boxing pattern (INVOKESTATIC):
//
//	Integer.valueOf(x) -> x
//	Boolean.valueOf(b) -> b
//
// Unboxing pattern (INVOKEVIRTUAL):
//
//	expr.intValue()    -> expr
//	expr.booleanValue() -> expr
func simplifyAutobox(e ast.Expression) (ast.Expression, bool) {
	inv, ok := e.(*ast.MethodInvocation)
	if !ok {
		return nil, false
	}

	// Check for boxing: static valueOf calls
	if inv.Kind == ast.InvokeStatic && len(inv.Args) == 1 {
		key := inv.Method.ClassName + "." + inv.Method.MethodName
		if boxingMethods[key] {
			return inv.Args[0], true
		}
	}

	// Check for unboxing: virtual xxxValue() calls
	if (inv.Kind == ast.InvokeVirtual || inv.Kind == ast.InvokeInterface) &&
		len(inv.Args) == 0 && inv.Object != nil {
		if unboxingMethods[inv.Method.MethodName] {
			return inv.Object, true
		}
	}

	return nil, false
}
