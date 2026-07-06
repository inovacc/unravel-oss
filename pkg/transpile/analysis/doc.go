// Package analysis provides deterministic source codebase analysis and mapping.
//
// It scans C/C++, Python, and Java source trees and produces structured reports containing:
//   - File discovery and LOC metrics (code, comments, blanks)
//   - Subsystem categorization based on file name patterns
//   - C/C++: Include dependency graphs (local + library detection)
//   - C/C++: Cross-file symbol tables (classes, functions, enums, namespaces)
//   - C/C++: Class inheritance hierarchies with interface candidate detection
//   - Python: Import dependency graphs with stdlib/third-party classification
//   - Python: Symbol tables (classes, functions, modules)
//   - Python: Class hierarchies with ABC/Protocol interface candidate detection
//   - Python: Framework detection (Django, Flask, FastAPI, etc.)
//
// The analysis output guides conversion strategy for togo, enabling
// subsystem-by-subsystem conversion with dependency-aware ordering.
package analysis
