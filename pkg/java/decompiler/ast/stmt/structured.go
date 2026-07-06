package stmt

import (
	"fmt"
	"strings"

	"github.com/inovacc/unravel-oss/pkg/java/decompiler/ast"
	"github.com/inovacc/unravel-oss/pkg/java/decompiler/types"
)

// StructuredIf represents a structured if/else statement.
type StructuredIf struct {
	Condition ast.Expression
	Then      Statement // body (usually a Block)
	Else      Statement // optional else branch
}

func NewStructuredIf(condition ast.Expression, then Statement, elseStmt Statement) *StructuredIf {
	return &StructuredIf{Condition: condition, Then: then, Else: elseStmt}
}

func (s *StructuredIf) Kind() StmtKind { return KindStructuredIf }

func (s *StructuredIf) Children() []Statement {
	if s.Else != nil {
		return []Statement{s.Then, s.Else}
	}

	return []Statement{s.Then}
}

func (s *StructuredIf) Expressions() []ast.Expression {
	return []ast.Expression{s.Condition}
}

func (s *StructuredIf) String() string {
	var b strings.Builder

	_, _ = fmt.Fprintf(&b, "if (%s) %s", s.Condition, s.Then)
	if s.Else != nil {
		_, _ = fmt.Fprintf(&b, " else %s", s.Else)
	}

	return b.String()
}

// StructuredWhile represents a while loop: while (cond) { body }
type StructuredWhile struct {
	Condition ast.Expression
	Body      Statement
	Label     string // optional loop label (for break/continue)
}

func NewStructuredWhile(condition ast.Expression, body Statement) *StructuredWhile {
	return &StructuredWhile{Condition: condition, Body: body}
}

func (s *StructuredWhile) Kind() StmtKind        { return KindStructuredWhile }
func (s *StructuredWhile) Children() []Statement { return []Statement{s.Body} }
func (s *StructuredWhile) Expressions() []ast.Expression {
	return []ast.Expression{s.Condition}
}

func (s *StructuredWhile) String() string {
	var b strings.Builder
	if s.Label != "" {
		b.WriteString(s.Label)
		b.WriteString(": ")
	}

	_, _ = fmt.Fprintf(&b, "while (%s) %s", s.Condition, s.Body)

	return b.String()
}

// StructuredDoWhile represents a do-while loop: do { body } while (cond);
type StructuredDoWhile struct {
	Condition ast.Expression
	Body      Statement
	Label     string
}

func NewStructuredDoWhile(condition ast.Expression, body Statement) *StructuredDoWhile {
	return &StructuredDoWhile{Condition: condition, Body: body}
}

func (s *StructuredDoWhile) Kind() StmtKind        { return KindStructuredDoWhile }
func (s *StructuredDoWhile) Children() []Statement { return []Statement{s.Body} }
func (s *StructuredDoWhile) Expressions() []ast.Expression {
	return []ast.Expression{s.Condition}
}

func (s *StructuredDoWhile) String() string {
	var b strings.Builder
	if s.Label != "" {
		b.WriteString(s.Label)
		b.WriteString(": ")
	}

	_, _ = fmt.Fprintf(&b, "do %s while (%s);", s.Body, s.Condition)

	return b.String()
}

// StructuredFor represents a for loop: for (init; cond; update) { body }
type StructuredFor struct {
	Init      Statement      // initializer (may be nil)
	Condition ast.Expression // loop condition (nil = infinite)
	Update    Statement      // update (may be nil)
	Body      Statement
	Label     string
}

func NewStructuredFor(init Statement, cond ast.Expression, update Statement, body Statement) *StructuredFor {
	return &StructuredFor{Init: init, Condition: cond, Update: update, Body: body}
}

func (s *StructuredFor) Kind() StmtKind { return KindStructuredFor }

func (s *StructuredFor) Children() []Statement {
	children := make([]Statement, 0, 3)
	if s.Init != nil {
		children = append(children, s.Init)
	}

	children = append(children, s.Body)
	if s.Update != nil {
		children = append(children, s.Update)
	}

	return children
}

func (s *StructuredFor) Expressions() []ast.Expression {
	if s.Condition != nil {
		return []ast.Expression{s.Condition}
	}

	return nil
}

func (s *StructuredFor) String() string {
	var b strings.Builder
	if s.Label != "" {
		b.WriteString(s.Label)
		b.WriteString(": ")
	}

	b.WriteString("for (")

	if s.Init != nil {
		b.WriteString(s.Init.String())
	}

	b.WriteString("; ")

	if s.Condition != nil {
		b.WriteString(s.Condition.String())
	}

	b.WriteString("; ")

	if s.Update != nil {
		b.WriteString(s.Update.String())
	}

	_, _ = fmt.Fprintf(&b, ") %s", s.Body)

	return b.String()
}

// StructuredForEach represents: for (Type var : iterable) { body }
type StructuredForEach struct {
	Variable ast.LValue
	Iterable ast.Expression
	Body     Statement
	Label    string
}

func NewStructuredForEach(variable ast.LValue, iterable ast.Expression, body Statement) *StructuredForEach {
	return &StructuredForEach{Variable: variable, Iterable: iterable, Body: body}
}

func (s *StructuredForEach) Kind() StmtKind        { return KindStructuredForEach }
func (s *StructuredForEach) Children() []Statement { return []Statement{s.Body} }
func (s *StructuredForEach) Expressions() []ast.Expression {
	return []ast.Expression{s.Variable, s.Iterable}
}

func (s *StructuredForEach) String() string {
	var b strings.Builder
	if s.Label != "" {
		b.WriteString(s.Label)
		b.WriteString(": ")
	}

	_, _ = fmt.Fprintf(&b, "for (%s %s : %s) %s",
		s.Variable.Type().Name(), s.Variable, s.Iterable, s.Body)

	return b.String()
}

// StructuredCase represents a case in a structured switch.
type StructuredCase struct {
	Values    []int32 // empty for default
	IsDefault bool
	Body      Statement // case body
}

// StructuredSwitch represents a structured switch statement with case bodies.
type StructuredSwitch struct {
	Value ast.Expression
	Cases []StructuredCase
}

func NewStructuredSwitch(value ast.Expression, cases []StructuredCase) *StructuredSwitch {
	return &StructuredSwitch{Value: value, Cases: cases}
}

func (s *StructuredSwitch) Kind() StmtKind { return KindStructuredSwitch }

func (s *StructuredSwitch) Children() []Statement {
	children := make([]Statement, 0, len(s.Cases))
	for _, c := range s.Cases {
		if c.Body != nil {
			children = append(children, c.Body)
		}
	}

	return children
}

func (s *StructuredSwitch) Expressions() []ast.Expression {
	return []ast.Expression{s.Value}
}

func (s *StructuredSwitch) String() string {
	var b strings.Builder

	_, _ = fmt.Fprintf(&b, "switch (%s) { ", s.Value)
	for _, c := range s.Cases {
		if c.IsDefault {
			b.WriteString("default: ")
		} else {
			for _, v := range c.Values {
				_, _ = fmt.Fprintf(&b, "case %d: ", v)
			}
		}

		if c.Body != nil {
			b.WriteString(c.Body.String())
			b.WriteByte(' ')
		}
	}

	b.WriteByte('}')

	return b.String()
}

// CatchClause represents a catch clause in a structured try.
type CatchClause struct {
	ExceptionType types.JavaType
	ExceptionVar  ast.LValue
	Body          Statement
}

// StructuredTry represents a structured try/catch/finally.
type StructuredTry struct {
	Body    Statement     // try body
	Catches []CatchClause // catch clauses
	Finally Statement     // optional finally block
}

func NewStructuredTry(body Statement, catches []CatchClause, finally Statement) *StructuredTry {
	return &StructuredTry{Body: body, Catches: catches, Finally: finally}
}

func (s *StructuredTry) Kind() StmtKind { return KindStructuredTry }

func (s *StructuredTry) Children() []Statement {
	children := make([]Statement, 0, 2+len(s.Catches))

	children = append(children, s.Body)
	for _, c := range s.Catches {
		children = append(children, c.Body)
	}

	if s.Finally != nil {
		children = append(children, s.Finally)
	}

	return children
}

func (s *StructuredTry) Expressions() []ast.Expression { return nil }

func (s *StructuredTry) String() string {
	var b strings.Builder

	_, _ = fmt.Fprintf(&b, "try %s", s.Body)
	for _, c := range s.Catches {
		if c.ExceptionType != nil {
			_, _ = fmt.Fprintf(&b, " catch (%s %s) %s",
				c.ExceptionType.Name(), c.ExceptionVar, c.Body)
		} else {
			_, _ = fmt.Fprintf(&b, " catch (%s) %s", c.ExceptionVar, c.Body)
		}
	}

	if s.Finally != nil {
		_, _ = fmt.Fprintf(&b, " finally %s", s.Finally)
	}

	return b.String()
}

// StructuredSynchronized represents: synchronized (object) { body }
type StructuredSynchronized struct {
	Object ast.Expression
	Body   Statement
}

func NewStructuredSynchronized(object ast.Expression, body Statement) *StructuredSynchronized {
	return &StructuredSynchronized{Object: object, Body: body}
}

func (s *StructuredSynchronized) Kind() StmtKind        { return KindStructuredSynchronized }
func (s *StructuredSynchronized) Children() []Statement { return []Statement{s.Body} }
func (s *StructuredSynchronized) Expressions() []ast.Expression {
	return []ast.Expression{s.Object}
}

func (s *StructuredSynchronized) String() string {
	return fmt.Sprintf("synchronized (%s) %s", s.Object, s.Body)
}

// BreakStatement represents: break [label];
type BreakStatement struct {
	Label string // empty for unlabeled break
}

func NewBreak(label string) *BreakStatement {
	return &BreakStatement{Label: label}
}

func (s *BreakStatement) Kind() StmtKind                { return KindBreak }
func (s *BreakStatement) Children() []Statement         { return nil }
func (s *BreakStatement) Expressions() []ast.Expression { return nil }

func (s *BreakStatement) String() string {
	if s.Label != "" {
		return fmt.Sprintf("break %s;", s.Label)
	}

	return "break;"
}

// ContinueStatement represents: continue [label];
type ContinueStatement struct {
	Label string // empty for unlabeled continue
}

func NewContinue(label string) *ContinueStatement {
	return &ContinueStatement{Label: label}
}

func (s *ContinueStatement) Kind() StmtKind                { return KindContinue }
func (s *ContinueStatement) Children() []Statement         { return nil }
func (s *ContinueStatement) Expressions() []ast.Expression { return nil }

func (s *ContinueStatement) String() string {
	if s.Label != "" {
		return fmt.Sprintf("continue %s;", s.Label)
	}

	return "continue;"
}
