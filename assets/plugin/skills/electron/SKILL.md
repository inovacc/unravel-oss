---
name: electron
description: Electron/Tauri desktop app analysis
---

For Electron apps:
1. `unravel_analyze` — full security analysis with risk scoring
2. `unravel_asar_extract` + `unravel_asar_search` — extract and search ASAR archives
3. `unravel_jsdeob_deobfuscate` — deobfuscate bundled JavaScript
4. `unravel_sourcemap_scan` — find and extract source maps
5. `unravel_extension_scan` — scan browser extensions

For Tauri apps, the same `unravel_analyze` works with Tauri-specific security checks.
