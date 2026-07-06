/*
Copyright (c) 2026 Security Research
*/

// Package garble detects obfuscation in Go binaries produced by the garble tool.
//
// Detection uses a weighted heuristic system that checks for missing build info,
// absent DWARF data, hashed symbol names, missing package paths, high-entropy
// strings, and other indicators.
//
// Entry points:
//   - Detect: analyze a binary and return detection result with confidence score
//   - ExtractInfo: extract binary metadata (Go version, build settings, arch, OS)
//   - ExtractStrings: extract strings with Shannon entropy categorization
//   - AnalyzeSymbols: analyze the symbol table for obfuscation indicators
//   - ScanDirectory: batch scan a directory for garbled Go binaries
package garble
