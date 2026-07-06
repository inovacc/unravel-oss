package ast

// Node is the interface implemented by all C++ AST nodes.
type Node interface {
	nodeType() string
	Pos() Position
}

// Position records the source location of an AST node.
type Position struct {
	Line   int `json:"line"`
	Column int `json:"column"`
}

// baseNode provides common position tracking for all AST nodes.
type baseNode struct {
	Position Position `json:"position"`
}

func (b baseNode) Pos() Position { return b.Position }

// TranslationUnit is the top-level node representing an entire C++ source file.
type TranslationUnit struct {
	baseNode

	FileName   string       `json:"file_name"`
	Includes   []*Include   `json:"includes,omitempty"`
	Namespaces []*Namespace `json:"namespaces,omitempty"`
	Decls      []Node       `json:"declarations,omitempty"`
}

func (*TranslationUnit) nodeType() string { return "TranslationUnit" }

// Include represents a #include directive.
type Include struct {
	baseNode

	Path   string `json:"path"`
	System bool   `json:"system"` // true for <header>, false for "header"
}

func (*Include) nodeType() string { return "Include" }

// Namespace represents a namespace declaration.
type Namespace struct {
	baseNode

	Name  string `json:"name"`
	Decls []Node `json:"declarations,omitempty"`
}

func (*Namespace) nodeType() string { return "Namespace" }

// UsingDecl represents a using declaration or using namespace directive.
type UsingDecl struct {
	baseNode

	Name      string `json:"name"`
	Namespace bool   `json:"namespace"` // true for "using namespace X"
}

func (*UsingDecl) nodeType() string { return "UsingDecl" }

// TypedefDecl represents a typedef or using alias declaration.
type TypedefDecl struct {
	baseNode

	Name       string   `json:"name"`
	Underlying *TypeRef `json:"underlying"`
}

func (*TypedefDecl) nodeType() string { return "TypedefDecl" }

// TypeRef represents a reference to a type, including qualifiers.
type TypeRef struct {
	Const        bool       `json:"const,omitempty"`
	Pointer      bool       `json:"pointer,omitempty"`
	Reference    bool       `json:"reference,omitempty"`
	RValueRef    bool       `json:"rvalue_ref,omitempty"`
	Name         string     `json:"name"`
	TemplateArgs []*TypeRef `json:"template_args,omitempty"`
	FuncPtr      bool       `json:"func_ptr,omitempty"`   // function pointer type
	ArraySize    string     `json:"array_size,omitempty"` // fixed array: "10", VLA: "n"
	Volatile     bool       `json:"volatile,omitempty"`
	Restrict     bool       `json:"restrict,omitempty"`
}

// ClassKind distinguishes class, struct, and union.
type ClassKind string

const (
	ClassKindClass  ClassKind = "class"
	ClassKindStruct ClassKind = "struct"
	ClassKindUnion  ClassKind = "union"
)

// Class represents a class, struct, or union declaration.
type Class struct {
	baseNode

	Kind           ClassKind           `json:"kind"`
	Name           string              `json:"name"`
	BaseClasses    []*BaseClass        `json:"base_classes,omitempty"`
	Fields         []*Field            `json:"fields,omitempty"`
	Methods        []*Method           `json:"methods,omitempty"`
	Constructors   []*Constructor      `json:"constructors,omitempty"`
	Destructor     *Destructor         `json:"destructor,omitempty"`
	Operators      []*OperatorOverload `json:"operators,omitempty"`
	Nested         []Node              `json:"nested,omitempty"`
	TemplateParams []*TemplateParam    `json:"template_params,omitempty"`
}

func (*Class) nodeType() string { return "Class" }

// BaseClass represents a base class in an inheritance list.
type BaseClass struct {
	Name   string `json:"name"`
	Access string `json:"access"` // public, protected, private
}

// Field represents a member variable of a class or struct.
type Field struct {
	baseNode

	Name   string   `json:"name"`
	Type   *TypeRef `json:"type"`
	Access string   `json:"access"` // public, protected, private
	Static bool     `json:"static,omitempty"`
}

func (*Field) nodeType() string { return "Field" }

// Enum represents an enum or enum class declaration.
type Enum struct {
	baseNode

	Name     string       `json:"name"`
	Scoped   bool         `json:"scoped"` // true for enum class
	Values   []*EnumValue `json:"values,omitempty"`
	BaseType *TypeRef     `json:"base_type,omitempty"`
}

func (*Enum) nodeType() string { return "Enum" }

// EnumValue represents a single enumerator.
type EnumValue struct {
	baseNode

	Name  string `json:"name"`
	Value string `json:"value,omitempty"`
}

func (*EnumValue) nodeType() string { return "EnumValue" }

// Function represents a free function declaration/definition.
type Function struct {
	baseNode

	Name           string           `json:"name"`
	ReturnType     *TypeRef         `json:"return_type"`
	Params         []*Parameter     `json:"params,omitempty"`
	Body           []Node           `json:"body,omitempty"`
	TemplateParams []*TemplateParam `json:"template_params,omitempty"`
}

func (*Function) nodeType() string { return "Function" }

// Method represents a member function of a class.
type Method struct {
	baseNode

	Name       string       `json:"name"`
	ReturnType *TypeRef     `json:"return_type"`
	Params     []*Parameter `json:"params,omitempty"`
	Body       []Node       `json:"body,omitempty"`
	Access     string       `json:"access"`
	Const      bool         `json:"const,omitempty"`
	Virtual    bool         `json:"virtual,omitempty"`
	Override   bool         `json:"override,omitempty"`
	Static     bool         `json:"static,omitempty"`
	Pure       bool         `json:"pure,omitempty"` // = 0
}

func (*Method) nodeType() string { return "Method" }

// Constructor represents a constructor.
type Constructor struct {
	baseNode

	Params   []*Parameter  `json:"params,omitempty"`
	Body     []Node        `json:"body,omitempty"`
	InitList []*MemberInit `json:"init_list,omitempty"`
	Access   string        `json:"access"`
}

func (*Constructor) nodeType() string { return "Constructor" }

// MemberInit represents a member initializer in a constructor init list.
type MemberInit struct {
	Member string `json:"member"`
	Value  Expr   `json:"value"`
}

// Destructor represents a destructor.
type Destructor struct {
	baseNode

	Body    []Node `json:"body,omitempty"`
	Virtual bool   `json:"virtual,omitempty"`
	Access  string `json:"access"`
}

func (*Destructor) nodeType() string { return "Destructor" }

// OperatorOverload represents an overloaded operator.
type OperatorOverload struct {
	baseNode

	Operator   string       `json:"operator"` // +, -, ==, <<, etc.
	ReturnType *TypeRef     `json:"return_type"`
	Params     []*Parameter `json:"params,omitempty"`
	Body       []Node       `json:"body,omitempty"`
	Access     string       `json:"access"`
}

func (*OperatorOverload) nodeType() string { return "OperatorOverload" }

// Parameter represents a function/method parameter.
type Parameter struct {
	baseNode

	Name    string   `json:"name"`
	Type    *TypeRef `json:"type"`
	Default string   `json:"default,omitempty"`
}

func (*Parameter) nodeType() string { return "Parameter" }

// Variable represents a variable declaration.
type Variable struct {
	baseNode

	Name   string   `json:"name"`
	Type   *TypeRef `json:"type"`
	Init   Expr     `json:"init,omitempty"`
	Const  bool     `json:"const,omitempty"`
	Static bool     `json:"static,omitempty"`
	Auto   bool     `json:"auto,omitempty"`
}

func (*Variable) nodeType() string { return "Variable" }

// TemplateDecl wraps a declaration with template parameters.
type TemplateDecl struct {
	baseNode

	Params []*TemplateParam `json:"params"`
	Decl   Node             `json:"declaration"`
}

func (*TemplateDecl) nodeType() string { return "TemplateDecl" }

// TemplateParam represents a template parameter.
type TemplateParam struct {
	Name    string `json:"name"`
	Kind    string `json:"kind"` // "typename", "class", "int", etc.
	Default string `json:"default,omitempty"`
}

// --- C-Specific Declarations ---

// GotoStmt represents a goto statement.
type GotoStmt struct {
	baseNode

	Label string `json:"label"`
}

func (*GotoStmt) nodeType() string { return "GotoStmt" }

// LabelStmt represents a labeled statement (goto target).
type LabelStmt struct {
	baseNode

	Label string `json:"label"`
	Stmt  Node   `json:"stmt,omitempty"`
}

func (*LabelStmt) nodeType() string { return "LabelStmt" }

// ExternDecl represents an extern declaration or extern "C" block.
type ExternDecl struct {
	baseNode

	Linkage string    `json:"linkage,omitempty"` // "C" for extern "C"
	Decls   []Node    `json:"declarations,omitempty"`
	Var     *Variable `json:"var,omitempty"` // for single extern variable
}

func (*ExternDecl) nodeType() string { return "ExternDecl" }

// FuncPtrDecl represents a function pointer typedef.
// e.g., typedef int (*callback_t)(void*, int);
type FuncPtrDecl struct {
	baseNode

	Name       string       `json:"name"`
	ReturnType *TypeRef     `json:"return_type"`
	Params     []*Parameter `json:"params,omitempty"`
}

func (*FuncPtrDecl) nodeType() string { return "FuncPtrDecl" }

// BitField represents a struct bitfield member.
// e.g., unsigned int flags : 3;
type BitField struct {
	baseNode

	Name  string   `json:"name"`
	Type  *TypeRef `json:"type"`
	Width int      `json:"width"` // number of bits
}

func (*BitField) nodeType() string { return "BitField" }

// --- Statements ---

// IfStmt represents an if/else statement.
type IfStmt struct {
	baseNode

	Init      Node   `json:"init,omitempty"` // C++17 if-init
	Condition Expr   `json:"condition"`
	Then      []Node `json:"then"`
	Else      []Node `json:"else,omitempty"`
}

func (*IfStmt) nodeType() string { return "IfStmt" }

// ForStmt represents a C-style for loop.
type ForStmt struct {
	baseNode

	Init      Node   `json:"init,omitempty"`
	Condition Expr   `json:"condition,omitempty"`
	Post      Expr   `json:"post,omitempty"`
	Body      []Node `json:"body"`
}

func (*ForStmt) nodeType() string { return "ForStmt" }

// RangeForStmt represents a range-based for loop.
type RangeForStmt struct {
	baseNode

	VarName string   `json:"var_name"`
	VarType *TypeRef `json:"var_type,omitempty"`
	Range   Expr     `json:"range"`
	Body    []Node   `json:"body"`
}

func (*RangeForStmt) nodeType() string { return "RangeForStmt" }

// WhileStmt represents a while loop.
type WhileStmt struct {
	baseNode

	Condition Expr   `json:"condition"`
	Body      []Node `json:"body"`
}

func (*WhileStmt) nodeType() string { return "WhileStmt" }

// DoWhileStmt represents a do-while loop.
type DoWhileStmt struct {
	baseNode

	Body      []Node `json:"body"`
	Condition Expr   `json:"condition"`
}

func (*DoWhileStmt) nodeType() string { return "DoWhileStmt" }

// SwitchStmt represents a switch statement.
type SwitchStmt struct {
	baseNode

	Condition Expr          `json:"condition"`
	Cases     []*CaseClause `json:"cases"`
}

func (*SwitchStmt) nodeType() string { return "SwitchStmt" }

// CaseClause represents a case or default clause in a switch.
type CaseClause struct {
	baseNode

	Value   Expr   `json:"value,omitempty"` // nil for default
	Body    []Node `json:"body"`
	Default bool   `json:"default,omitempty"`
}

func (*CaseClause) nodeType() string { return "CaseClause" }

// ReturnStmt represents a return statement.
type ReturnStmt struct {
	baseNode

	Value Expr `json:"value,omitempty"`
}

func (*ReturnStmt) nodeType() string { return "ReturnStmt" }

// BreakStmt represents a break statement.
type BreakStmt struct {
	baseNode
}

func (*BreakStmt) nodeType() string { return "BreakStmt" }

// ContinueStmt represents a continue statement.
type ContinueStmt struct {
	baseNode
}

func (*ContinueStmt) nodeType() string { return "ContinueStmt" }

// TryBlock represents a try-catch block.
type TryBlock struct {
	baseNode

	Body    []Node         `json:"body"`
	Catches []*CatchClause `json:"catches"`
}

func (*TryBlock) nodeType() string { return "TryBlock" }

// CatchClause represents a catch handler.
type CatchClause struct {
	baseNode

	ParamName string   `json:"param_name,omitempty"`
	ParamType *TypeRef `json:"param_type,omitempty"` // nil for catch(...)
	Body      []Node   `json:"body"`
}

func (*CatchClause) nodeType() string { return "CatchClause" }

// ThrowExpr represents a throw expression.
type ThrowExpr struct {
	baseNode

	Value Expr `json:"value,omitempty"` // nil for rethrow
}

func (*ThrowExpr) nodeType() string { return "ThrowExpr" }

// LambdaExpr represents a lambda expression.
type LambdaExpr struct {
	baseExpr

	Captures   []string     `json:"captures,omitempty"`
	Params     []*Parameter `json:"params,omitempty"`
	ReturnType *TypeRef     `json:"return_type,omitempty"`
	Body       []Node       `json:"body"`
}

func (*LambdaExpr) nodeType() string { return "LambdaExpr" }

// --- Expressions ---

// Expr is the interface for all expression nodes.
type Expr interface {
	Node
	exprNode()
}

// baseExpr provides common behavior for expression nodes.
type baseExpr struct {
	baseNode
}

func (baseExpr) exprNode() {}

// Assignment represents an assignment expression.
type Assignment struct {
	baseExpr

	Target   Expr   `json:"target"`
	Operator string `json:"operator"` // =, +=, -=, etc.
	Value    Expr   `json:"value"`
}

func (*Assignment) nodeType() string { return "Assignment" }

// BinaryExpr represents a binary operation.
type BinaryExpr struct {
	baseExpr

	Left     Expr   `json:"left"`
	Operator string `json:"operator"`
	Right    Expr   `json:"right"`
}

func (*BinaryExpr) nodeType() string { return "BinaryExpr" }

// UnaryExpr represents a unary operation.
type UnaryExpr struct {
	baseExpr

	Operator string `json:"operator"`
	Operand  Expr   `json:"operand"`
	Prefix   bool   `json:"prefix"`
}

func (*UnaryExpr) nodeType() string { return "UnaryExpr" }

// CallExpr represents a function or method call.
type CallExpr struct {
	baseExpr

	Func Expr   `json:"func"`
	Args []Expr `json:"args,omitempty"`
}

func (*CallExpr) nodeType() string { return "CallExpr" }

// MemberExpr represents member access (obj.member or obj->member).
type MemberExpr struct {
	baseExpr

	Object Expr   `json:"object"`
	Member string `json:"member"`
	Arrow  bool   `json:"arrow,omitempty"` // true for ->
}

func (*MemberExpr) nodeType() string { return "MemberExpr" }

// ScopeExpr represents scope resolution (Namespace::name).
type ScopeExpr struct {
	baseExpr

	Scope string `json:"scope"`
	Name  string `json:"name"`
}

func (*ScopeExpr) nodeType() string { return "ScopeExpr" }

// IndexExpr represents array/subscript access.
type IndexExpr struct {
	baseExpr

	Object Expr `json:"object"`
	Index  Expr `json:"index"`
}

func (*IndexExpr) nodeType() string { return "IndexExpr" }

// CastExpr represents a type cast (static_cast, dynamic_cast, C-style cast).
type CastExpr struct {
	baseExpr

	Kind    string   `json:"kind"` // static_cast, dynamic_cast, reinterpret_cast, const_cast, c_style
	Type    *TypeRef `json:"type"`
	Operand Expr     `json:"operand"`
}

func (*CastExpr) nodeType() string { return "CastExpr" }

// NewExpr represents a new expression.
type NewExpr struct {
	baseExpr

	Type *TypeRef `json:"type"`
	Args []Expr   `json:"args,omitempty"`
}

func (*NewExpr) nodeType() string { return "NewExpr" }

// DeleteExpr represents a delete expression.
type DeleteExpr struct {
	baseExpr

	Operand Expr `json:"operand"`
	Array   bool `json:"array,omitempty"`
}

func (*DeleteExpr) nodeType() string { return "DeleteExpr" }

// Literal represents a literal value.
type Literal struct {
	baseExpr

	Kind  string `json:"kind"` // int, float, string, char, bool, nullptr
	Value string `json:"value"`
}

func (*Literal) nodeType() string { return "Literal" }

// Identifier represents a name reference.
type Identifier struct {
	baseExpr

	Name string `json:"name"`
}

func (*Identifier) nodeType() string { return "Identifier" }

// RawExpr is a fallback for expressions the builder cannot fully parse.
type RawExpr struct {
	baseExpr

	Text string `json:"text"`
}

func (*RawExpr) nodeType() string { return "RawExpr" }

// RawStmt is a fallback for statements the builder cannot fully parse.
type RawStmt struct {
	baseNode

	Text string `json:"text"`
}

func (*RawStmt) nodeType() string { return "RawStmt" }

// ExprStmt wraps an expression as a statement.
type ExprStmt struct {
	baseNode

	Expr Expr `json:"expr"`
}

func (*ExprStmt) nodeType() string { return "ExprStmt" }
