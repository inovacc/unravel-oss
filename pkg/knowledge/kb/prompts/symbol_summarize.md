---
op: symbol_summarize
description: Summarize a single function, method, or class body in 2 lines
language_hint: any
output_format: json
schema: '{summary: string, confidence: number}'
max_tokens: 1024
---
You are summarizing one source-level symbol. Read the body carefully and
produce a strict JSON object with two keys:

- `summary`: 2 short lines describing what the symbol does and why
- `confidence`: number in [0, 1] indicating how sure you are

Body:

```
{body}
```

Return JSON only — no prose, no code fences.
