package patterns

import (
	"strings"

	"github.com/inovacc/unravel-oss/pkg/java/decompiler/ast"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/ast/stmt"
)

// collapseAssertions detects assert patterns in statement lists and
// returns a count of how many were found. This is informational only
// as the AST doesn't have an assert statement type yet — it annotates
// the output with a comment.
//
// javac compiles `assert cond : msg` into:
//
//	if (!$assertionsDisabled) {
//	    if (!cond) {
//	        throw new AssertionError(msg);
//	    }
//	}
func collapseAssertions(stmts []stmt.Statement) ([]stmt.Statement, int) {
	if len(stmts) == 0 {
		return stmts, 0
	}

	count := 0
	result := make([]stmt.Statement, 0, len(stmts))

	for _, s := range stmts {
		if detectAssertionPattern(s) {
			count++
			// Replace the compiler-generated if block with a comment marker
			// using a string literal that renders as a comment.
			comment := assertCommentFromIf(s)
			marker := stmt.NewExpressionStatement(
				ast.NewStringLiteral(comment),
			)
			result = append(result, marker)
		} else {
			result = append(result, s)
		}
	}

	return result, count
}

// detectAssertionPattern returns true if a statement matches the javac
// assert compilation pattern:
//
//	if (!$assertionsDisabled) {
//	    if (!cond) { throw new AssertionError(...); }
//	}
func detectAssertionPattern(s stmt.Statement) bool {
	sif, ok := s.(*stmt.StructuredIf)
	if !ok {
		return false
	}

	// Outer condition must reference $assertionsDisabled
	condStr := sif.Condition.String()
	if !strings.Contains(condStr, "$assertionsDisabled") {
		return false
	}

	// The then-branch must eventually throw AssertionError.
	return bodyThrowsAssertionError(sif.Then)
}

// bodyThrowsAssertionError returns true if the statement (or its immediate
// children) contains a throw of AssertionError. This handles both:
//   - Direct: throw new AssertionError(msg);
//   - Wrapped in an inner if: if (!cond) { throw new AssertionError(msg); }
//   - Wrapped in a Block containing the above
func bodyThrowsAssertionError(s stmt.Statement) bool {
	if s == nil {
		return false
	}

	text := s.String()

	// Check for AssertionError (the standard Java class name).
	if strings.Contains(text, "AssertionError") {
		return true
	}

	return false
}

// assertCommentFromIf extracts a readable assert description from the
// compiler-generated if statement. It inspects the inner condition
// and any AssertionError message argument to reconstruct:
//
//	/* assert <cond> */        or
//	/* assert <cond> : <msg> */
func assertCommentFromIf(s stmt.Statement) string {
	sif, ok := s.(*stmt.StructuredIf)
	if !ok {
		return "/* assert */"
	}

	// Try to extract the inner if's condition for a more descriptive comment.
	innerCond := extractInnerAssertCondition(sif.Then)
	if innerCond != "" {
		return "/* assert " + innerCond + " */"
	}

	return "/* assert */"
}

// extractInnerAssertCondition digs into the then-branch to find the
// negated condition from `if (!cond) { throw ... }`. Returns the
// condition string (without the negation, i.e., the original assert condition).
func extractInnerAssertCondition(s stmt.Statement) string {
	// Unwrap Block if needed
	if blk, ok := s.(*stmt.Block); ok && len(blk.Stmts) > 0 {
		return extractInnerAssertCondition(blk.Stmts[0])
	}

	innerIf, ok := s.(*stmt.StructuredIf)
	if !ok {
		return ""
	}

	condStr := innerIf.Condition.String()

	// The inner condition is typically `!cond` (negated). Strip the negation
	// to recover the original assert condition.
	condStr = strings.TrimSpace(condStr)
	if after, ok0 := strings.CutPrefix(condStr, "!"); ok0 {
		condStr = after
		condStr = strings.TrimSpace(condStr)
		// Remove surrounding parens if present: !(cond) -> cond
		if strings.HasPrefix(condStr, "(") && strings.HasSuffix(condStr, ")") {
			condStr = condStr[1 : len(condStr)-1]
		}
	}

	return condStr
}
