---
op: fact_resolve
description: Resolve one open fact gap from supporting module evidence
language_hint: any
output_format: json
schema: '{value: string, evidence_ids: [int], confidence: number}'
max_tokens: 2048
---
You are filling one open fact gap about an application. Use only the
evidence below to decide. If the evidence is insufficient, say so by
returning a low confidence score and an empty evidence_ids array.

Gap instruction:

{gap_prompt}

Evidence (modules JSON):

{evidence_json}

Return strict JSON:

```
{"value": "...", "evidence_ids": [12, 34], "confidence": 0.0}
```
