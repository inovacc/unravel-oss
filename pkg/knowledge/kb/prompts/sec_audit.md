---
op: sec_audit
description: Identify concrete security-relevant findings in a module body
language_hint: any
output_format: json
schema: '{findings: [{severity: string, kind: string, note: string}], confidence: number}'
max_tokens: 2048
---
You are performing a focused security review on a single module body.
Only report findings that are evidenced by the code itself — do not
speculate about callers or infrastructure.

Body:

```
{body}
```

Return strict JSON:

```
{"findings": [{"severity": "low|medium|high|critical", "kind": "...", "note": "..."}], "confidence": 0.0}
```
