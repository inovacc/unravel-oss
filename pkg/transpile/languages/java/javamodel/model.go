// Package javamodel defines the intermediate representation types for Java source code.
package javamodel

// NodeType identifies the kind of Java construct.
type NodeType string

const (
	NodePackage        NodeType = "package"
	NodeImport         NodeType = "import"
	NodeClass          NodeType = "class"
	NodeInterface      NodeType = "interface"
	NodeEnum           NodeType = "enum"
	NodeAnnotationDecl NodeType = "annotation_decl"
	NodeMethod         NodeType = "method"
	NodeConstructor    NodeType = "constructor"
	NodeField          NodeType = "field"
	NodeBlock          NodeType = "block"
	NodeIf             NodeType = "if"
	NodeFor            NodeType = "for"
	NodeForEach        NodeType = "for_each"
	NodeWhile          NodeType = "while"
	NodeDoWhile        NodeType = "do_while"
	NodeSwitch         NodeType = "switch"
	NodeCase           NodeType = "case"
	NodeTry            NodeType = "try"
	NodeCatch          NodeType = "catch"
	NodeFinally        NodeType = "finally"
	NodeThrow          NodeType = "throw"
	NodeReturn         NodeType = "return"
	NodeAssign         NodeType = "assign"
	NodeCall           NodeType = "call"
	NodeExpr           NodeType = "expression"
	NodeLambda         NodeType = "lambda"
	NodeAnnotationUse  NodeType = "annotation_use"
	NodeBreak          NodeType = "break"
	NodeContinue       NodeType = "continue"
	NodeRecord         NodeType = "record"
)

// Node is the intermediate representation of a Java AST node.
type Node struct {
	Type        NodeType          `json:"type"`
	Name        string            `json:"name,omitempty"`
	Value       string            `json:"value,omitempty"`
	Children    []*Node           `json:"children,omitempty"`
	Params      []*Param          `json:"params,omitempty"`
	Annotations []string          `json:"annotations,omitempty"`
	Modifiers   []string          `json:"modifiers,omitempty"`
	TypeParams  []string          `json:"type_params,omitempty"`
	Implements  []string          `json:"implements,omitempty"`
	Extends     string            `json:"extends,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	Line        int               `json:"line"`
	Column      int               `json:"column"`

	// Cond holds the source condition/iterable for structured control-flow
	// nodes (if/while test, for-each iterable). Children holds the body.
	Cond string `json:"cond,omitempty"`
	// Orelse holds the structured else branch (If) or for/while else body;
	// an elif-like chain nests a single NodeIf.
	Orelse []*Node `json:"orelse,omitempty"`
	// Target holds the loop variable(s) for a for-each loop.
	Target string `json:"target,omitempty"`
}

// Param represents a method/constructor parameter.
type Param struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	Modifiers   []string `json:"modifiers,omitempty"`
	Annotations []string `json:"annotations,omitempty"`
	IsVarargs   bool     `json:"is_varargs,omitempty"`
}

// Module is the top-level IR representing a complete Java file.
type Module struct {
	FileName string  `json:"file_name"`
	Package  string  `json:"package,omitempty"`
	Imports  []*Node `json:"imports"`
	Types    []*Node `json:"types"`
}
