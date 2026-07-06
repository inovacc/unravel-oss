// Package ast defines semantic C/C++ AST node types and provides a builder
// that transforms an ANTLR4 parse tree into a typed AST. The AST captures
// the meaning of C/C++ constructs — C++ classes, templates, and namespaces,
// as well as C-specific constructs like function pointer typedefs, goto/labels,
// extern declarations, and bitfields — rather than raw parse tree structure.
package ast
