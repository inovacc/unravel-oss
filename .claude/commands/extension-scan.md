---
description: Scan browser extensions for security issues and stealth tools
allowed-tools: mcp__unravel__unravel_extension_scan, mcp__unravel__unravel_extension_analyze, mcp__unravel__unravel_extension_search, mcp__unravel__unravel_extension_list, Read, Glob, Bash
---
Scan browser extensions: $ARGUMENTS

1. Run unravel_extension_scan (with browser filter if specified)
2. For HIGH/CRITICAL risk extensions, run unravel_extension_analyze for deep analysis
3. Summarize total extensions, risk distribution, and stealth/cheating flags found
