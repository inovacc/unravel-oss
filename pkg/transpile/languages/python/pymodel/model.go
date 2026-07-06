// Package pymodel defines the intermediate representation types for Python source code.
package pymodel

// NodeType identifies the kind of Python construct.
type NodeType string

const (
	NodeModule     NodeType = "module"
	NodeImport     NodeType = "import"
	NodeClass      NodeType = "class"
	NodeFunction   NodeType = "function"
	NodeAssign     NodeType = "assign"
	NodeReturn     NodeType = "return"
	NodeIf         NodeType = "if"
	NodeFor        NodeType = "for"
	NodeWhile      NodeType = "while"
	NodeCall       NodeType = "call"
	NodeExpr       NodeType = "expression"
	NodeBinOp      NodeType = "binop"
	NodeAttribute  NodeType = "attribute"
	NodeSubscript  NodeType = "subscript"
	NodeList       NodeType = "list"
	NodeDict       NodeType = "dict"
	NodeTuple      NodeType = "tuple"
	NodeSet        NodeType = "set"
	NodeLiteral    NodeType = "literal"
	NodeName       NodeType = "name"
	NodeDecorator  NodeType = "decorator"
	NodeWith       NodeType = "with"
	NodeTry        NodeType = "try"
	NodeRaise      NodeType = "raise"
	NodeYield      NodeType = "yield"
	NodeLambda     NodeType = "lambda"
	NodeComprehend NodeType = "comprehension"
	NodePass       NodeType = "pass"
	NodeBreak      NodeType = "break"
	NodeContinue   NodeType = "continue"
	NodeComment    NodeType = "comment"
)

// Node is the intermediate representation of a Python AST node.
type Node struct {
	Type       NodeType          `json:"type"`
	Name       string            `json:"name,omitempty"`
	Value      string            `json:"value,omitempty"`
	Children   []*Node           `json:"children,omitempty"`
	Params     []*Param          `json:"params,omitempty"`
	Decorators []string          `json:"decorators,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
	Line       int               `json:"line"`
	Column     int               `json:"column"`

	// Cond holds the source condition/iterable expression for structured
	// control-flow nodes (if/elif test, while test, for iterable). Children
	// holds the structured then/body statements.
	Cond string `json:"cond,omitempty"`
	// Orelse holds the structured else branch for If/For/While nodes. For an
	// elif chain, Orelse contains a single nested NodeIf.
	Orelse []*Node `json:"orelse,omitempty"`
	// Target holds the loop variable(s) for a for-loop (e.g. "i" or "k, v").
	Target string `json:"target,omitempty"`
}

// Param represents a function parameter with optional type annotation and default.
type Param struct {
	Name       string `json:"name"`
	TypeHint   string `json:"type_hint,omitempty"`
	Default    string `json:"default,omitempty"`
	IsVariadic bool   `json:"is_variadic,omitempty"`
	IsKwarg    bool   `json:"is_kwarg,omitempty"`
}

// Module is the top-level IR representing a complete Python file.
type Module struct {
	FileName string  `json:"file_name"`
	Imports  []*Node `json:"imports"`
	Body     []*Node `json:"body"`
}
