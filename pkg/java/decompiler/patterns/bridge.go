package patterns

import (
	"strings"

	"github.com/inovacc/unravel-oss/pkg/java/decompiler/ast/stmt"
)

// isBridgeMethod returns true if the method body appears to be a synthetic bridge.
// Bridge methods are single-statement delegators that cast and forward to another method.
//
// javac generates bridge methods for:
//   - Covariant return types (bridge calls the more specific return type override)
//   - Generic type erasure (bridge casts Object to the erased type and delegates)
//   - Inner class access methods (access$000, access$100, etc.)
//
// Typical patterns:
//
//	// Covariant return bridge
//	return (SpecificType) this.realMethod(arg0, arg1);
//
//	// Generic erasure bridge
//	return this.compareTo((MyClass) arg0);
//
//	// Inner class accessor
//	return Outer.access$000(this$0);
//
//	// Void delegation bridge
//	this.realMethod((CastType) arg0);
func isBridgeMethod(stmts []stmt.Statement) bool {
	flat := flattenBridgeBody(stmts)

	// Bridge methods have exactly 1 effective statement
	if len(flat) != 1 {
		return false
	}

	s := flat[0]
	str := s.String()

	// Check for inner class access methods (access$NNN pattern)
	if isAccessBridge(str) {
		return true
	}

	switch v := s.(type) {
	case *stmt.ReturnStatement:
		// return expr; -- check if expr is a simple delegation (method call, possibly cast)
		return isDelegationExpr(v.Value.String())

	case *stmt.ExpressionStatement:
		// expr; -- check if it's a void delegation
		return isDelegationExpr(v.Expr.String())
	}

	return false
}

// flattenBridgeBody extracts the effective statement list from a method body.
// If the body is a single Block, unwrap it. Filter out nop statements.
func flattenBridgeBody(stmts []stmt.Statement) []stmt.Statement {
	// Unwrap single block
	if len(stmts) == 1 {
		if b, ok := stmts[0].(*stmt.Block); ok {
			stmts = b.Stmts
		}
	}

	// Filter out nops
	result := make([]stmt.Statement, 0, len(stmts))
	for _, s := range stmts {
		if s.Kind() != stmt.KindNop {
			result = append(result, s)
		}
	}

	return result
}

// isAccessBridge checks if the statement string contains an inner class
// access method pattern like "access$000", "access$100", "access$200", etc.
func isAccessBridge(s string) bool {
	return strings.Contains(s, "access$")
}

// isDelegationExpr checks whether an expression string looks like a simple
// method delegation, possibly with a cast. This is a heuristic check.
//
// Matches patterns like:
//
//	this.method(args)
//	((Type) this.method(args))
//	ClassName.method(args)
//	(Type) obj.method(args)
func isDelegationExpr(s string) bool {
	// Strip outer parentheses and cast if present
	clean := stripOuterCast(s)

	// Must contain a method invocation (has parentheses for args)
	if !strings.Contains(clean, "(") {
		return false
	}

	// Must contain a dot (object.method or Class.method)
	if !strings.Contains(clean, ".") {
		return false
	}

	// Should not contain control flow keywords (not a complex expression)
	for _, kw := range []string{"if ", "while ", "for ", "switch ", "new ", "&&", "||"} {
		if strings.Contains(clean, kw) {
			return false
		}
	}

	// Count semicolons -- a delegation should have at most one (the trailing one)
	if strings.Count(clean, ";") > 1 {
		return false
	}

	return true
}

// stripOuterCast removes a leading cast expression like "(Type) " from a string.
// Also removes wrapping parentheses. This is a best-effort heuristic.
func stripOuterCast(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, ";")
	s = strings.TrimSpace(s)

	// Remove wrapping parens: ((Type) expr) -> (Type) expr
	for len(s) > 2 && s[0] == '(' && s[len(s)-1] == ')' {
		// Only unwrap if the opening paren matches the closing one
		depth := 0
		matchPos := -1
		for i, c := range s {
			if c == '(' {
				depth++
			} else if c == ')' {
				depth--
				if depth == 0 {
					matchPos = i
					break
				}
			}
		}

		if matchPos == len(s)-1 {
			s = s[1 : len(s)-1]
			s = strings.TrimSpace(s)
		} else {
			break
		}
	}

	// Strip leading cast: (Type) expr -> expr
	if len(s) > 0 && s[0] == '(' {
		closeIdx := strings.IndexByte(s, ')')
		if closeIdx > 0 && closeIdx < len(s)-1 {
			// Check if the content inside parens looks like a type (no dots with parens after)
			inside := s[1:closeIdx]
			if looksLikeTypeName(inside) {
				s = strings.TrimSpace(s[closeIdx+1:])
			}
		}
	}

	return s
}

// looksLikeTypeName returns true if the string could be a Java type name.
// Used to distinguish casts from method calls in parenthesized expressions.
func looksLikeTypeName(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) == 0 {
		return false
	}

	// Type names don't contain operators, semicolons, or method call parens
	for _, forbidden := range []string{"(", ")", ";", "=", "+", "-", "*", "/"} {
		if strings.Contains(s, forbidden) {
			return false
		}
	}

	return true
}
