---
description: Run full unravel security analysis on an Electron/Tauri application
allowed-tools: mcp__unravel__unravel_analyze, mcp__unravel__unravel_asar_extract, mcp__unravel__unravel_asar_dump, mcp__unravel__unravel_asar_search, mcp__unravel__unravel_cert_info, mcp__unravel__unravel_cert_scan, mcp__unravel__unravel_garble_detect, Read, Glob, Grep, Bash
---
Perform comprehensive security analysis on: $ARGUMENTS

1. Run unravel_analyze on the target
2. If Electron app, run unravel_asar_dump on any .asar files found
3. If Go binaries are present, run unravel_garble_detect on them
4. If PE/ELF binaries are present, run unravel_cert_info on them
5. Summarize risk level, stealth features, and key findings in a clear report
