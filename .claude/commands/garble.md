---
description: Detect garble obfuscation in Go binaries
allowed-tools: mcp__unravel__unravel_garble_detect, mcp__unravel__unravel_garble_info, mcp__unravel__unravel_garble_symbols, mcp__unravel__unravel_garble_strings, mcp__unravel__unravel_garble_scan, Read, Glob, Bash
---
Analyze for garble obfuscation: $ARGUMENTS

1. If single binary: run unravel_garble_detect, then unravel_garble_info and unravel_garble_symbols for details
2. If directory: run unravel_garble_scan to batch check all Go binaries
3. Report confidence level, heuristic breakdown, and key findings
