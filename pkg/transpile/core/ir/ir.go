package ir

// Node is the interface for all IR nodes.
type Node interface {
	irNode() string
}

// TypeKind classifies IR types.
type TypeKind string

const (
	KindPrimitive TypeKind = "primitive"
	KindSlice     TypeKind = "slice"
	KindMap       TypeKind = "map"
	KindPointer   TypeKind = "pointer"
	KindInterface TypeKind = "interface"
	KindStruct    TypeKind = "struct"
	KindGeneric   TypeKind = "generic"
	KindFunc      TypeKind = "func"
	KindChannel   TypeKind = "channel"
	KindUnion     TypeKind = "union"
)

// TypeRef represents a language-agnostic type reference.
type TypeRef struct {
	Kind       TypeKind   `json:"kind"`
	Name       string     `json:"name"`
	ElemType   *TypeRef   `json:"elem_type,omitempty"`   // for slice, pointer, channel
	KeyType    *TypeRef   `json:"key_type,omitempty"`    // for map
	ValType    *TypeRef   `json:"val_type,omitempty"`    // for map
	TypeParams []*TypeRef `json:"type_params,omitempty"` // for generic
	Fields     []*TypeRef `json:"fields,omitempty"`      // for func (params/returns)
}

// Module is the top-level IR node representing a translation unit.
type Module struct {
	PackageName string    `json:"package_name"`
	Imports     []*Import `json:"imports,omitempty"`
	Decls       []Node    `json:"declarations,omitempty"`
	SourceFile  string    `json:"source_file"`
}

func (*Module) irNode() string { return "Module" }

// Import represents a Go import.
type Import struct {
	Path  string `json:"path"`
	Alias string `json:"alias,omitempty"`
}

func (*Import) irNode() string { return "Import" }

// TypeDeclKind distinguishes struct, interface, and enum declarations.
type TypeDeclKind string

const (
	TypeDeclStruct    TypeDeclKind = "struct"
	TypeDeclInterface TypeDeclKind = "interface"
	TypeDeclEnum      TypeDeclKind = "enum"
)

// TypeDecl represents a type declaration (struct, interface, enum).
type TypeDecl struct {
	Kind       TypeDeclKind `json:"kind"`
	Name       string       `json:"name"`
	Fields     []*FieldDecl `json:"fields,omitempty"`
	Methods    []*FuncDecl  `json:"methods,omitempty"`  // interface methods (signatures only) or struct methods
	Values     []*EnumVal   `json:"values,omitempty"`   // enum values
	Embedded   []string     `json:"embedded,omitempty"` // embedded types (composition from inheritance)
	TypeParams []string     `json:"type_params,omitempty"`
	Comment    string       `json:"comment,omitempty"`
}

func (*TypeDecl) irNode() string { return "TypeDecl" }

// FieldDecl represents a struct field.
type FieldDecl struct {
	Name    string   `json:"name"`
	Type    *TypeRef `json:"type"`
	Tag     string   `json:"tag,omitempty"`
	Comment string   `json:"comment,omitempty"`
}

func (*FieldDecl) irNode() string { return "FieldDecl" }

// EnumVal represents a single enum value.
type EnumVal struct {
	Name  string `json:"name"`
	Value string `json:"value,omitempty"`
}

// FuncDecl represents a function or method declaration.
type FuncDecl struct {
	Name       string       `json:"name"`
	Receiver   *ParamDecl   `json:"receiver,omitempty"` // nil for free functions
	Params     []*ParamDecl `json:"params,omitempty"`
	Returns    []*ParamDecl `json:"returns,omitempty"`
	Body       []Node       `json:"body,omitempty"`
	TypeParams []string     `json:"type_params,omitempty"`
	Comment    string       `json:"comment,omitempty"`
}

func (*FuncDecl) irNode() string { return "FuncDecl" }

// ParamDecl represents a function parameter or return value.
type ParamDecl struct {
	Name string   `json:"name,omitempty"`
	Type *TypeRef `json:"type"`
}

func (*ParamDecl) irNode() string { return "ParamDecl" }

// VarDecl represents a variable declaration.
type VarDecl struct {
	Name  string   `json:"name"`
	Type  *TypeRef `json:"type,omitempty"`
	Value Expr     `json:"value,omitempty"`
	Const bool     `json:"const,omitempty"`
}

func (*VarDecl) irNode() string { return "VarDecl" }

// --- Statements ---

// Block represents a sequence of statements.
type Block struct {
	Stmts []Node `json:"stmts"`
}

func (*Block) irNode() string { return "Block" }

// IfStmt represents an if/else statement.
type IfStmt struct {
	Init Node   `json:"init,omitempty"`
	Cond Expr   `json:"cond"`
	Then []Node `json:"then"`
	Else []Node `json:"else,omitempty"`
}

func (*IfStmt) irNode() string { return "IfStmt" }

// ForStmt represents a C-style for loop.
type ForStmt struct {
	Init Node   `json:"init,omitempty"`
	Cond Expr   `json:"cond,omitempty"`
	Post Expr   `json:"post,omitempty"`
	Body []Node `json:"body"`
}

func (*ForStmt) irNode() string { return "ForStmt" }

// RangeStmt represents a range-based for loop.
type RangeStmt struct {
	Key   string `json:"key,omitempty"`
	Value string `json:"value,omitempty"`
	Range Expr   `json:"range"`
	Body  []Node `json:"body"`
}

func (*RangeStmt) irNode() string { return "RangeStmt" }

// SwitchStmt represents a switch statement.
type SwitchStmt struct {
	Tag   Expr          `json:"tag,omitempty"`
	Cases []*CaseClause `json:"cases"`
}

func (*SwitchStmt) irNode() string { return "SwitchStmt" }

// CaseClause represents a case in a switch.
type CaseClause struct {
	Values  []Expr `json:"values,omitempty"` // nil for default
	Body    []Node `json:"body"`
	Default bool   `json:"default,omitempty"`
}

func (*CaseClause) irNode() string { return "CaseClause" }

// ReturnStmt represents a return statement.
type ReturnStmt struct {
	Values []Expr `json:"values,omitempty"`
}

func (*ReturnStmt) irNode() string { return "ReturnStmt" }

// AssignStmt represents an assignment.
type AssignStmt struct {
	LHS []Expr `json:"lhs"`
	Op  string `json:"op"` // =, :=, +=, etc.
	RHS []Expr `json:"rhs"`
}

func (*AssignStmt) irNode() string { return "AssignStmt" }

// ExprStmt wraps an expression used as a statement.
type ExprStmt struct {
	Expr Expr `json:"expr"`
}

func (*ExprStmt) irNode() string { return "ExprStmt" }

// DeferStmt represents a defer statement (from RAII/destructors).
type DeferStmt struct {
	Call Expr `json:"call"`
}

func (*DeferStmt) irNode() string { return "DeferStmt" }

// ErrorHandling represents Go error handling (replaces try/catch).
type ErrorHandling struct {
	Call   Expr   `json:"call"`
	ErrVar string `json:"err_var"`
	Body   []Node `json:"body"` // error handling body
}

func (*ErrorHandling) irNode() string { return "ErrorHandling" }

// BranchStmt represents break/continue.
type BranchStmt struct {
	Kind string `json:"kind"` // "break" or "continue"
}

func (*BranchStmt) irNode() string { return "BranchStmt" }

// GotoStmt represents a goto statement in IR.
type GotoStmt struct {
	Label string `json:"label"`
}

func (*GotoStmt) irNode() string { return "GotoStmt" }

// LabelStmt represents a labeled statement in IR.
type LabelStmt struct {
	Label string `json:"label"`
	Stmt  Node   `json:"stmt,omitempty"`
}

func (*LabelStmt) irNode() string { return "LabelStmt" }

// RawStmt is a fallback for code that cannot be represented in IR.
type RawStmt struct {
	Text    string `json:"text"`
	Comment string `json:"comment,omitempty"`
}

func (*RawStmt) irNode() string { return "RawStmt" }

// --- Expressions ---

// Expr is the interface for all IR expressions.
type Expr interface {
	Node
	exprNode()
}

type baseExpr struct{}

func (baseExpr) exprNode() {}

// CallExpr represents a function call.
type CallExpr struct {
	baseExpr

	Func string `json:"func"`
	Args []Expr `json:"args,omitempty"`
}

func (*CallExpr) irNode() string { return "CallExpr" }

// MethodCallExpr represents a method call on a receiver.
type MethodCallExpr struct {
	baseExpr

	Receiver Expr   `json:"receiver"`
	Method   string `json:"method"`
	Args     []Expr `json:"args,omitempty"`
}

func (*MethodCallExpr) irNode() string { return "MethodCallExpr" }

// BinaryExpr represents a binary operation.
type BinaryExpr struct {
	baseExpr

	Left  Expr   `json:"left"`
	Op    string `json:"op"`
	Right Expr   `json:"right"`
}

func (*BinaryExpr) irNode() string { return "BinaryExpr" }

// UnaryExpr represents a unary operation.
type UnaryExpr struct {
	baseExpr

	Op      string `json:"op"`
	Operand Expr   `json:"operand"`
	Prefix  bool   `json:"prefix"`
}

func (*UnaryExpr) irNode() string { return "UnaryExpr" }

// LiteralExpr represents a literal value.
type LiteralExpr struct {
	baseExpr

	Kind  string `json:"kind"` // int, float, string, bool, nil
	Value string `json:"value"`
}

func (*LiteralExpr) irNode() string { return "LiteralExpr" }

// IdentExpr represents an identifier reference.
type IdentExpr struct {
	baseExpr

	Name string `json:"name"`
}

func (*IdentExpr) irNode() string { return "IdentExpr" }

// SelectorExpr represents field/method access (a.b).
type SelectorExpr struct {
	baseExpr

	X   Expr   `json:"x"`
	Sel string `json:"sel"`
}

func (*SelectorExpr) irNode() string { return "SelectorExpr" }

// IndexExpr represents array/slice/map indexing.
type IndexExpr struct {
	baseExpr

	X     Expr `json:"x"`
	Index Expr `json:"index"`
}

func (*IndexExpr) irNode() string { return "IndexExpr" }

// SliceExpr represents a slice expression (a[low:high]).
type SliceExpr struct {
	baseExpr

	X    Expr `json:"x"`
	Low  Expr `json:"low,omitempty"`
	High Expr `json:"high,omitempty"`
}

func (*SliceExpr) irNode() string { return "SliceExpr" }

// TypeAssertExpr represents a type assertion (x.(T)).
type TypeAssertExpr struct {
	baseExpr

	X    Expr     `json:"x"`
	Type *TypeRef `json:"type"`
}

func (*TypeAssertExpr) irNode() string { return "TypeAssertExpr" }

// CompositeLitExpr represents a composite literal ({key: value}).
type CompositeLitExpr struct {
	baseExpr

	Type   *TypeRef    `json:"type,omitempty"`
	Fields []*KeyValue `json:"fields,omitempty"`
}

func (*CompositeLitExpr) irNode() string { return "CompositeLitExpr" }

// KeyValue represents a key-value pair in a composite literal.
type KeyValue struct {
	Key   Expr `json:"key,omitempty"`
	Value Expr `json:"value"`
}

// FuncLitExpr represents a function literal / closure.
type FuncLitExpr struct {
	baseExpr

	Params  []*ParamDecl `json:"params,omitempty"`
	Returns []*ParamDecl `json:"returns,omitempty"`
	Body    []Node       `json:"body"`
}

func (*FuncLitExpr) irNode() string { return "FuncLitExpr" }

// RawExpr is a fallback for expressions that cannot be fully represented.
type RawExpr struct {
	baseExpr

	Text string `json:"text"`
}

func (*RawExpr) irNode() string { return "RawExpr" }

// MakeExpr represents a make() call for slices, maps, channels.
type MakeExpr struct {
	baseExpr

	Type *TypeRef `json:"type"`
	Len  Expr     `json:"len,omitempty"`
	Cap  Expr     `json:"cap,omitempty"`
}

func (*MakeExpr) irNode() string { return "MakeExpr" }

// AddressExpr represents taking the address (&x).
type AddressExpr struct {
	baseExpr

	X Expr `json:"x"`
}

func (*AddressExpr) irNode() string { return "AddressExpr" }

// DerefExpr represents dereferencing (*x).
type DerefExpr struct {
	baseExpr

	X Expr `json:"x"`
}

func (*DerefExpr) irNode() string { return "DerefExpr" }
