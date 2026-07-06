/*
Copyright (c) 2026 Security Research
*/
package patterns

import (
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/ast"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/ast/stmt"
)

// StaticFieldInit represents an extracted static field initializer.
type StaticFieldInit struct {
	FieldName string
	Value     ast.Expression
}

// ExtractStaticInits extracts simple field initializer assignments from
// a <clinit> method's statement list. Returns assignments that can be
// inlined into field declarations.
//
// Recognized patterns:
//
//	ClassName.field = <literal>;
//	ClassName.field = new Foo(...);
func ExtractStaticInits(stmts []stmt.Statement) []StaticFieldInit {
	var inits []StaticFieldInit

	for _, s := range stmts {
		assign, ok := s.(*stmt.AssignmentStatement)
		if !ok {
			continue
		}

		// Target must be a static field access
		fa, ok := assign.Target.(*ast.StaticFieldAccess)
		if !ok {
			continue
		}

		// Value must be a simple expression (literal, new, method call)
		if isInlinableValue(assign.Value) {
			inits = append(inits, StaticFieldInit{
				FieldName: fa.Field.FieldName,
				Value:     assign.Value,
			})
		}
	}

	return inits
}

// isInlinableValue returns true if the expression is simple enough to
// inline into a field declaration.
func isInlinableValue(e ast.Expression) bool {
	if e == nil {
		return false
	}

	switch e.(type) {
	case *ast.Literal:
		return true
	case *ast.MethodInvocation:
		// new ClassName(args) renders as invocation with <init>
		return true
	case *ast.ArithmeticOperation:
		// String concatenation
		return true
	default:
		return false
	}
}
