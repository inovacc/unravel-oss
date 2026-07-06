package stmt

import "github.com/inovacc/unravel-oss/pkg/java/decompiler/ast"

// Statement represents a Java statement in the decompiled AST.
type Statement interface {
	// Kind returns the statement type for switching.
	Kind() StmtKind

	// Children returns sub-statements (for tree traversal).
	Children() []Statement

	// Expressions returns expressions contained in this statement.
	Expressions() []ast.Expression

	// String returns a human-readable representation.
	String() string
}

// StmtKind identifies the type of statement.
type StmtKind int

const (
	KindNop StmtKind = iota
	KindAssignment
	KindExpression
	KindReturn
	KindReturnVoid
	KindThrow
	KindIf
	KindGoto
	KindSwitch
	KindTry
	KindCatch
	KindBlock
	KindMonitorEnter
	KindMonitorExit
	KindCompound
	KindLabeled

	// Structured statement kinds (produced by Op03)
	KindStructuredIf
	KindStructuredWhile
	KindStructuredDoWhile
	KindStructuredFor
	KindStructuredForEach
	KindStructuredSwitch
	KindStructuredTry
	KindStructuredSynchronized
	KindBreak
	KindContinue
)
