---
op: topic_classify
description: Classify a module body into 1-3 canonical topic labels
language_hint: any
output_format: json
schema: '{topics: [string], confidence: number}'
max_tokens: 512
---
Classify the following module body into 1-3 canonical topics from this
vocabulary: messages, presence, calls, crypto, auth, storage, ui, ipc,
network, telemetry, e2ee.

Body excerpt:

```
{body}
```

Return strict JSON:

```
{"topics": ["..."], "confidence": 0.0}
```
