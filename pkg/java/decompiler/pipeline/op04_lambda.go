package pipeline

import (
	"strings"

	"github.com/inovacc/unravel-oss/pkg/java/decompiler/ast"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/ast/stmt"
)

// RewriteLambdas converts DynamicInvocation expressions (from invokedynamic)
// into LambdaExpression or MethodReferenceExpression where possible.
func RewriteLambdas(nodes []*Op03Node) {
	for _, n := range nodes {
		if n.Statement != nil {
			n.Statement = rewriteLambdaStatement(n.Statement)
		}
	}
}

func rewriteLambdaStatement(s stmt.Statement) stmt.Statement {
	switch st := s.(type) {
	case *stmt.ReturnStatement:
		st.Value = rewriteLambdaExpr(st.Value)
	case *stmt.AssignmentStatement:
		st.Value = rewriteLambdaExpr(st.Value)
	case *stmt.ExpressionStatement:
		st.Expr = rewriteLambdaExpr(st.Expr)
	case *stmt.StructuredIf:
		st.Condition = rewriteLambdaExpr(st.Condition)

		st.Then = rewriteLambdaStatement(st.Then)
		if st.Else != nil {
			st.Else = rewriteLambdaStatement(st.Else)
		}
	case *stmt.StructuredWhile:
		st.Condition = rewriteLambdaExpr(st.Condition)
		st.Body = rewriteLambdaStatement(st.Body)
	case *stmt.StructuredDoWhile:
		st.Condition = rewriteLambdaExpr(st.Condition)
		st.Body = rewriteLambdaStatement(st.Body)
	case *stmt.StructuredFor:
		st.Condition = rewriteLambdaExpr(st.Condition)
		st.Body = rewriteLambdaStatement(st.Body)
	case *stmt.StructuredSwitch:
		st.Value = rewriteLambdaExpr(st.Value)
		for i := range st.Cases {
			if st.Cases[i].Body != nil {
				st.Cases[i].Body = rewriteLambdaStatement(st.Cases[i].Body)
			}
		}
	case *stmt.StructuredTry:
		st.Body = rewriteLambdaStatement(st.Body)
		for i := range st.Catches {
			st.Catches[i].Body = rewriteLambdaStatement(st.Catches[i].Body)
		}

		if st.Finally != nil {
			st.Finally = rewriteLambdaStatement(st.Finally)
		}
	case *stmt.Block:
		for i := range st.Stmts {
			st.Stmts[i] = rewriteLambdaStatement(st.Stmts[i])
		}
	}

	return s
}

func rewriteLambdaExpr(e ast.Expression) ast.Expression {
	if e == nil {
		return nil
	}

	switch expr := e.(type) {
	case *ast.DynamicInvocation:
		if result := tryConvertLambda(expr); result != nil {
			return result
		}
		// Recurse into args
		for i := range expr.Args {
			expr.Args[i] = rewriteLambdaExpr(expr.Args[i])
		}

		return expr

	case *ast.MethodInvocation:
		for i := range expr.Args {
			expr.Args[i] = rewriteLambdaExpr(expr.Args[i])
		}

		if expr.Object != nil {
			expr.Object = rewriteLambdaExpr(expr.Object)
		}

		return expr

	case *ast.AssignmentExpression:
		expr.Value = rewriteLambdaExpr(expr.Value)
		return expr

	case *ast.ArithmeticOperation:
		expr.LHS = rewriteLambdaExpr(expr.LHS)
		expr.RHS = rewriteLambdaExpr(expr.RHS)

		return expr

	case *ast.ComparisonOperation:
		expr.LHS = rewriteLambdaExpr(expr.LHS)
		expr.RHS = rewriteLambdaExpr(expr.RHS)

		return expr

	case *ast.BooleanOperation:
		expr.LHS = rewriteLambdaExpr(expr.LHS)
		expr.RHS = rewriteLambdaExpr(expr.RHS)

		return expr

	case *ast.TernaryExpression:
		expr.Condition = rewriteLambdaExpr(expr.Condition)
		expr.TrueExpr = rewriteLambdaExpr(expr.TrueExpr)
		expr.FalseExpr = rewriteLambdaExpr(expr.FalseExpr)

		return expr

	case *ast.CastExpression:
		expr.Operand = rewriteLambdaExpr(expr.Operand)
		return expr

	case *ast.NegationExpression:
		expr.Operand = rewriteLambdaExpr(expr.Operand)
		return expr
	}

	return e
}

// tryConvertLambda attempts to convert a DynamicInvocation to a lambda or method reference.
// In Java bytecode, lambdas are compiled as invokedynamic calls to LambdaMetafactory.
// The Name field typically contains the functional interface method name (e.g., "run", "apply", "test").
func tryConvertLambda(d *ast.DynamicInvocation) ast.Expression {
	// Check if this looks like a lambda metafactory call.
	// Lambda DynamicInvocation args are the captured variables.
	// The Name is the SAM method name from the functional interface.
	if !isLambdaPattern(d) {
		return nil
	}

	// If the captured args include a single method invocation or field access,
	// try to emit a method reference.
	if ref := tryMethodReference(d); ref != nil {
		return ref
	}

	// Build a lambda expression with the captured variables as implicit context.
	return ast.NewLambdaExpression(nil, nil, d.JType)
}

// isLambdaPattern checks if a DynamicInvocation looks like a lambda.
// In practice, all invokedynamic in Java 8+ that are lambda-based will
// use the lambda metafactory bootstrap.
func isLambdaPattern(d *ast.DynamicInvocation) bool {
	// Common lambda SAM method names from standard functional interfaces
	switch d.Name {
	case "run", "call", "apply", "accept", "test", "get", "getAsInt",
		"getAsLong", "getAsDouble", "compare", "compareTo", "supply",
		"consume", "execute", "handle", "invoke":
		return true
	}
	// The descriptor also gives a hint: lambda factories return a functional interface
	return d.Descriptor != "" && !strings.Contains(d.Name, "$")
}

// tryMethodReference checks if the lambda can be expressed as a method reference.
// For example: System.out::println instead of x -> System.out.println(x).
func tryMethodReference(d *ast.DynamicInvocation) ast.Expression {
	// A method reference pattern: single captured arg that is a method or field access.
	// Without full bootstrap method resolution, we can detect simple patterns.
	if len(d.Args) == 1 {
		if invoke, ok := d.Args[0].(*ast.MethodInvocation); ok {
			if invoke.Kind == ast.InvokeStatic && len(invoke.Args) == 0 {
				return ast.NewStaticMethodReference(
					invoke.Method.ClassName,
					invoke.Method.MethodName,
					d.JType,
				)
			}
		}
	}

	return nil
}

// RemoveSyntheticBridges removes synthetic bridge method calls by inlining the target.
// Bridge methods are generated by the compiler for covariant return types and
// generic type erasure. They simply delegate to the actual implementation.
func RemoveSyntheticBridges(nodes []*Op03Node) {
	for _, n := range nodes {
		if n.Statement != nil {
			n.Statement = removeBridgeStatement(n.Statement)
		}
	}
}

func removeBridgeStatement(s stmt.Statement) stmt.Statement {
	switch st := s.(type) {
	case *stmt.ReturnStatement:
		st.Value = removeBridgeExpr(st.Value)
	case *stmt.AssignmentStatement:
		st.Value = removeBridgeExpr(st.Value)
	case *stmt.ExpressionStatement:
		st.Expr = removeBridgeExpr(st.Expr)
	case *stmt.StructuredIf:
		st.Then = removeBridgeStatement(st.Then)
		if st.Else != nil {
			st.Else = removeBridgeStatement(st.Else)
		}
	case *stmt.StructuredWhile:
		st.Body = removeBridgeStatement(st.Body)
	case *stmt.StructuredDoWhile:
		st.Body = removeBridgeStatement(st.Body)
	case *stmt.StructuredFor:
		st.Body = removeBridgeStatement(st.Body)
	case *stmt.Block:
		for i := range st.Stmts {
			st.Stmts[i] = removeBridgeStatement(st.Stmts[i])
		}
	}

	return s
}

func removeBridgeExpr(e ast.Expression) ast.Expression {
	if e == nil {
		return nil
	}

	switch expr := e.(type) {
	case *ast.MethodInvocation:
		// Detect bridge method pattern: a method that just casts and forwards.
		// Pattern: bridgeMethod(args...) where bridge casts return of realMethod(args...)
		if isBridgeMethodCall(expr) && len(expr.Args) > 0 {
			if cast, ok := expr.Args[0].(*ast.CastExpression); ok {
				return cast.Operand
			}
		}
		// Recurse into args
		for i := range expr.Args {
			expr.Args[i] = removeBridgeExpr(expr.Args[i])
		}

		if expr.Object != nil {
			expr.Object = removeBridgeExpr(expr.Object)
		}
	case *ast.CastExpression:
		expr.Operand = removeBridgeExpr(expr.Operand)
	}

	return e
}

// isBridgeMethodCall detects synthetic bridge method calls.
// Bridge methods typically have names like "access$000" or contain "$".
func isBridgeMethodCall(m *ast.MethodInvocation) bool {
	if m.Method == nil {
		return false
	}

	name := m.Method.MethodName
	// Synthetic accessor pattern: access$NNN
	if strings.HasPrefix(name, "access$") {
		return true
	}

	return false
}
