// Package codegen generates Go source code from the language-agnostic IR.
// It walks the IR tree and emits formatted Go code, using goimports for
// final formatting. Nodes that cannot be generated deterministically
// are marked for LLM fallback.
package codegen
