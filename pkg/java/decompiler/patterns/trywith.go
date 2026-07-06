package patterns

import (
	"strings"

	"github.com/inovacc/unravel-oss/pkg/java/decompiler/ast/stmt"
)

// collapseTryWithResources detects try/finally patterns that represent
// try-with-resources and annotates them. Returns transformed list and count.
//
// javac compiles try-with-resources:
//
//	try (Resource r = new Resource()) { ...body... }
//
// into:
//
//	Resource r = new Resource();
//	try {
//	    ...body...
//	} finally {
//	    if (r != null) {
//	        r.close();
//	    }
//	}
//
// Or a more complex variant with addSuppressed for exception handling.
// This function detects these patterns by checking for assignment + try/finally
// pairs where the finally block calls .close() on the assigned variable.
func collapseTryWithResources(stmts []stmt.Statement) ([]stmt.Statement, int) {
	count := 0

	// Flatten: if the input is a single Block, use its children.
	flat := flattenToList(stmts)

	for i := range flat {
		// Look for pattern: assignment at [i], StructuredTry at [i+1]
		if i+1 >= len(flat) {
			continue
		}

		assign, isAssign := flat[i].(*stmt.AssignmentStatement)
		if !isAssign {
			continue
		}

		tryStmt, isTry := flat[i+1].(*stmt.StructuredTry)
		if !isTry {
			continue
		}

		// Must have a finally block
		if tryStmt.Finally == nil {
			continue
		}

		// Check if the finally block contains a .close() call on the assigned variable
		varName := assign.Target.String()
		finallyStr := tryStmt.Finally.String()

		if containsCloseCall(finallyStr, varName) {
			count++
		}
	}

	// Also recursively walk into nested structures to find try-with-resources
	// patterns inside method bodies, loops, etc.
	count += walkForTryWithResources(flat)

	// We don't transform the AST (too risky), just return the original statements
	// with the detection count.
	return stmts, count
}

// containsCloseCall checks whether a finally block string representation
// contains a .close() call on the given variable name.
func containsCloseCall(finallyStr, varName string) bool {
	// Check for explicit "varName.close()" pattern
	if strings.Contains(finallyStr, varName+".close()") {
		return true
	}

	// Also check for the common pattern where the finally just calls close()
	// without the variable prefix (e.g., when inlined or simplified)
	if strings.Contains(finallyStr, ".close()") {
		// If the variable name also appears somewhere in the finally block,
		// it's likely a try-with-resources pattern
		if strings.Contains(finallyStr, varName) {
			return true
		}
	}

	return false
}

// walkForTryWithResources recursively walks into structured statements
// looking for standalone StructuredTry nodes whose finally block contains
// a .close() call (even without a preceding assignment visible at this level).
func walkForTryWithResources(stmts []stmt.Statement) int {
	count := 0

	for _, s := range stmts {
		switch v := s.(type) {
		case *stmt.StructuredTry:
			// Check the try body and catches recursively
			if bodyList := stmtToList(v.Body); len(bodyList) > 0 {
				_, inner := collapseTryWithResources(bodyList)
				count += inner
			}
			for _, c := range v.Catches {
				if catchList := stmtToList(c.Body); len(catchList) > 0 {
					_, inner := collapseTryWithResources(catchList)
					count += inner
				}
			}
		case *stmt.Block:
			_, inner := collapseTryWithResources(v.Stmts)
			count += inner
		case *stmt.StructuredIf:
			if thenList := stmtToList(v.Then); len(thenList) > 0 {
				_, inner := collapseTryWithResources(thenList)
				count += inner
			}
			if v.Else != nil {
				if elseList := stmtToList(v.Else); len(elseList) > 0 {
					_, inner := collapseTryWithResources(elseList)
					count += inner
				}
			}
		case *stmt.StructuredWhile:
			if bodyList := stmtToList(v.Body); len(bodyList) > 0 {
				_, inner := collapseTryWithResources(bodyList)
				count += inner
			}
		case *stmt.StructuredDoWhile:
			if bodyList := stmtToList(v.Body); len(bodyList) > 0 {
				_, inner := collapseTryWithResources(bodyList)
				count += inner
			}
		case *stmt.StructuredFor:
			if bodyList := stmtToList(v.Body); len(bodyList) > 0 {
				_, inner := collapseTryWithResources(bodyList)
				count += inner
			}
		case *stmt.StructuredForEach:
			if bodyList := stmtToList(v.Body); len(bodyList) > 0 {
				_, inner := collapseTryWithResources(bodyList)
				count += inner
			}
		case *stmt.StructuredSynchronized:
			if bodyList := stmtToList(v.Body); len(bodyList) > 0 {
				_, inner := collapseTryWithResources(bodyList)
				count += inner
			}
		}
	}

	return count
}

// flattenToList returns a flat list of statements. If the input is a single
// Block, its children are returned; otherwise the input is returned as-is.
func flattenToList(stmts []stmt.Statement) []stmt.Statement {
	if len(stmts) == 1 {
		if b, ok := stmts[0].(*stmt.Block); ok {
			return b.Stmts
		}
	}

	return stmts
}

// stmtToList converts a single statement into a list. Blocks are unwrapped.
func stmtToList(s stmt.Statement) []stmt.Statement {
	if s == nil {
		return nil
	}

	if b, ok := s.(*stmt.Block); ok {
		return b.Stmts
	}

	return []stmt.Statement{s}
}
