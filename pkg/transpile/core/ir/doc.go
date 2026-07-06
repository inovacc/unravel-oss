// Package ir defines a language-agnostic intermediate representation (IR)
// used between the C/C++ AST and Go code generation stages. The IR captures
// programming concepts (types, functions, control flow) without being
// specific to C, C++, or Go. It includes support for C-specific constructs
// like goto/labels and union types.
package ir
