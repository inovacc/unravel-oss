// Package converter orchestrates the source-to-Go conversion pipeline.
// It supports multiple source languages (C/C++, Python) via the language
// registry and three conversion modes:
//   - Raw mode: sends source directly to Claude for conversion
//   - AST mode: parses source → AST → IR → adapt → codegen → Go code
//   - Hybrid mode: AST pipeline with LLM fallback for complex sections
package converter
