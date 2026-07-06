---
name: npm
description: npm package security analysis and MCP server auditing
---

For npm packages:
1. `unravel_npm_info` — registry metadata
2. `unravel_npm_download` — download and extract
3. `unravel_npm_analyze` — security scan (network, exec, secrets, obfuscation, supply chain)

For MCP servers: use `npm mcp <dir>` to extract tool inventory, SDK version, and transport type.
For batch analysis: use `npm batch <pkg1> <pkg2>` to analyze multiple packages.
For version comparison: use `npm diff <pkg> <v1> <v2>` to detect changes between versions.
