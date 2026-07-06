package pipeline

import (
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/ast"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/ast/stmt"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/types"
)

// SimplifyExpressions walks the statement tree and simplifies expressions.
func SimplifyExpressions(nodes []*Op03Node) {
	for _, n := range nodes {
		if n.Statement != nil {
			n.Statement = simplifyStatement(n.Statement)
		}
	}
}

func simplifyStatement(s stmt.Statement) stmt.Statement {
	switch st := s.(type) {
	case *stmt.ReturnStatement:
		st.Value = simplifyExpr(st.Value)
	case *stmt.ThrowStatement:
		st.Value = simplifyExpr(st.Value)
	case *stmt.AssignmentStatement:
		st.Value = simplifyExpr(st.Value)
	case *stmt.ExpressionStatement:
		st.Expr = simplifyExpr(st.Expr)
	case *stmt.StructuredIf:
		st.Condition = simplifyExpr(st.Condition)

		st.Then = simplifyStatement(st.Then)
		if st.Else != nil {
			st.Else = simplifyStatement(st.Else)
		}
	case *stmt.StructuredWhile:
		st.Condition = simplifyExpr(st.Condition)
		st.Body = simplifyStatement(st.Body)
	case *stmt.StructuredDoWhile:
		st.Condition = simplifyExpr(st.Condition)
		st.Body = simplifyStatement(st.Body)
	case *stmt.StructuredFor:
		st.Condition = simplifyExpr(st.Condition)
		st.Body = simplifyStatement(st.Body)
	case *stmt.StructuredSwitch:
		st.Value = simplifyExpr(st.Value)
		for i := range st.Cases {
			if st.Cases[i].Body != nil {
				st.Cases[i].Body = simplifyStatement(st.Cases[i].Body)
			}
		}
	case *stmt.StructuredTry:
		st.Body = simplifyStatement(st.Body)
		for i := range st.Catches {
			st.Catches[i].Body = simplifyStatement(st.Catches[i].Body)
		}

		if st.Finally != nil {
			st.Finally = simplifyStatement(st.Finally)
		}
	case *stmt.StructuredSynchronized:
		st.Object = simplifyExpr(st.Object)
		st.Body = simplifyStatement(st.Body)
	case *stmt.Block:
		for i := range st.Stmts {
			st.Stmts[i] = simplifyStatement(st.Stmts[i])
		}
	}

	return s
}

func simplifyExpr(e ast.Expression) ast.Expression {
	if e == nil {
		return nil
	}

	switch expr := e.(type) {
	case *ast.ArithmeticOperation:
		expr.LHS = simplifyExpr(expr.LHS)
		expr.RHS = simplifyExpr(expr.RHS)
		// Constant folding for integer arithmetic
		if result := foldIntArith(expr); result != nil {
			return result
		}
		// Simplify x + 0 → x, x * 1 → x, etc.
		if result := simplifyIdentityArith(expr); result != nil {
			return result
		}

		return expr

	case *ast.ComparisonOperation:
		expr.LHS = simplifyExpr(expr.LHS)
		expr.RHS = simplifyExpr(expr.RHS)

		return expr

	case *ast.BooleanOperation:
		expr.LHS = simplifyExpr(expr.LHS)
		expr.RHS = simplifyExpr(expr.RHS)

		return expr

	case *ast.NegationExpression:
		expr.Operand = simplifyExpr(expr.Operand)
		// Double negation: !!x → x
		if inner, ok := expr.Operand.(*ast.NegationExpression); ok {
			return inner.Operand
		}

		return expr

	case *ast.CastExpression:
		expr.Operand = simplifyExpr(expr.Operand)
		// Remove identity cast: (int)intValue → intValue
		if !expr.Forced && expr.Operand.Type() != nil && expr.TargetType != nil {
			if expr.Operand.Type().Name() == expr.TargetType.Name() {
				return expr.Operand
			}
		}

		return expr

	case *ast.TernaryExpression:
		expr.Condition = simplifyExpr(expr.Condition)
		expr.TrueExpr = simplifyExpr(expr.TrueExpr)
		expr.FalseExpr = simplifyExpr(expr.FalseExpr)
		// Simplify: true ? a : b → a, false ? a : b → b
		if expr.Condition == ast.LitTrue {
			return expr.TrueExpr
		}

		if expr.Condition == ast.LitFalse {
			return expr.FalseExpr
		}

		return expr

	case *ast.MethodInvocation:
		for i := range expr.Args {
			expr.Args[i] = simplifyExpr(expr.Args[i])
		}

		if expr.Object != nil {
			expr.Object = simplifyExpr(expr.Object)
		}

		return expr

	case *ast.AssignmentExpression:
		expr.Value = simplifyExpr(expr.Value)
		return expr
	}

	return e
}

// foldIntArith folds constant integer arithmetic.
func foldIntArith(expr *ast.ArithmeticOperation) ast.Expression {
	lhs, lok := expr.LHS.(*ast.Literal)

	rhs, rok := expr.RHS.(*ast.Literal)
	if !lok || !rok {
		return nil
	}

	if lhs.Kind != ast.LitInt || rhs.Kind != ast.LitInt {
		return nil
	}

	l := lhs.IntVal
	r := rhs.IntVal

	switch expr.Op {
	case ast.OpAdd:
		return ast.NewIntLiteral(int32(l + r))
	case ast.OpSub:
		return ast.NewIntLiteral(int32(l - r))
	case ast.OpMul:
		return ast.NewIntLiteral(int32(l * r))
	case ast.OpDiv:
		if r != 0 {
			return ast.NewIntLiteral(int32(l / r))
		}
	case ast.OpRem:
		if r != 0 {
			return ast.NewIntLiteral(int32(l % r))
		}
	}

	return nil
}

// simplifyIdentityArith simplifies identity operations.
func simplifyIdentityArith(expr *ast.ArithmeticOperation) ast.Expression {
	// x + 0 → x, 0 + x → x
	if expr.Op == ast.OpAdd {
		if isIntZero(expr.RHS) {
			return expr.LHS
		}

		if isIntZero(expr.LHS) {
			return expr.RHS
		}
	}
	// x - 0 → x
	if expr.Op == ast.OpSub {
		if isIntZero(expr.RHS) {
			return expr.LHS
		}
	}
	// x * 1 → x, 1 * x → x
	if expr.Op == ast.OpMul {
		if isIntOne(expr.RHS) {
			return expr.LHS
		}

		if isIntOne(expr.LHS) {
			return expr.RHS
		}
	}
	// x / 1 → x
	if expr.Op == ast.OpDiv {
		if isIntOne(expr.RHS) {
			return expr.LHS
		}
	}
	// x * 0 → 0, 0 * x → 0
	if expr.Op == ast.OpMul {
		if isIntZero(expr.RHS) || isIntZero(expr.LHS) {
			return ast.LitIntZero
		}
	}

	return nil
}

func isIntZero(e ast.Expression) bool {
	return e == ast.LitIntZero
}

func isIntOne(e ast.Expression) bool {
	return e == ast.LitIntOne
}

// RemoveRedundantCasts removes casts that cast to the same type.
func RemoveRedundantCasts(nodes []*Op03Node) {
	SimplifyExpressions(nodes)
}

// SimplifyBooleans simplifies boolean expressions:
// - x == true → x
// - x == false → !x
// - x != true → !x
// - x != false → x
func SimplifyBooleans(nodes []*Op03Node) {
	for _, n := range nodes {
		if n.Statement != nil {
			n.Statement = simplifyBoolStatement(n.Statement)
		}
	}
}

func simplifyBoolStatement(s stmt.Statement) stmt.Statement {
	switch st := s.(type) {
	case *stmt.StructuredIf:
		st.Condition = simplifyBoolExpr(st.Condition)

		st.Then = simplifyBoolStatement(st.Then)
		if st.Else != nil {
			st.Else = simplifyBoolStatement(st.Else)
		}
	case *stmt.StructuredWhile:
		st.Condition = simplifyBoolExpr(st.Condition)
		st.Body = simplifyBoolStatement(st.Body)
	case *stmt.StructuredDoWhile:
		st.Condition = simplifyBoolExpr(st.Condition)
		st.Body = simplifyBoolStatement(st.Body)
	case *stmt.Block:
		for i := range st.Stmts {
			st.Stmts[i] = simplifyBoolStatement(st.Stmts[i])
		}
	}

	return s
}

func simplifyBoolExpr(e ast.Expression) ast.Expression {
	cmp, ok := e.(*ast.ComparisonOperation)
	if !ok {
		return e
	}

	// x == true → x
	if cmp.Op == ast.CmpEq && cmp.RHS == ast.LitTrue {
		if cmp.LHS.Type() == types.TypeBoolean {
			return cmp.LHS
		}
	}
	// x == false → !x
	if cmp.Op == ast.CmpEq && cmp.RHS == ast.LitFalse {
		if cmp.LHS.Type() == types.TypeBoolean {
			return ast.NewNegationExpression(cmp.LHS)
		}
	}
	// x != true → !x
	if cmp.Op == ast.CmpNe && cmp.RHS == ast.LitTrue {
		if cmp.LHS.Type() == types.TypeBoolean {
			return ast.NewNegationExpression(cmp.LHS)
		}
	}
	// x != false → x
	if cmp.Op == ast.CmpNe && cmp.RHS == ast.LitFalse {
		if cmp.LHS.Type() == types.TypeBoolean {
			return cmp.LHS
		}
	}

	return e
}
