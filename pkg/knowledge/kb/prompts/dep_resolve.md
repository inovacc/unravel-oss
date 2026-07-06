---
op: dep_resolve
description: Resolve a dependency string to a concrete sibling module or external package
language_hint: any
output_format: json
schema: '{kind: string, target: string, confidence: number}'
max_tokens: 512
---
Given a single dependency string emitted by a module, decide whether it
resolves to a sibling module in this app or to an external package.

Dependency string:

{dep}

Sibling-module candidates:

{candidates_json}

Return strict JSON:

```
{"kind": "sibling|external|builtin|unresolved", "target": "...", "confidence": 0.0}
```
