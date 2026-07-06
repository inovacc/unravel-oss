// Package pipeline orchestrates the 4-stage Java bytecode decompilation process:
//
//   - Op01: Decode bytecode instructions and build a control flow graph (CFG)
//   - Op02: Simulate the JVM stack to produce typed expressions
//   - Op03: Structure control flow (loops, conditionals, try/catch) from gotos
//   - Op04: Apply final transforms (expression simplification, statement cleanup)
//
// The pipeline entry point is [Decompile], which takes parsed class file data
// and returns structured AST statements suitable for Java source generation.
package pipeline
