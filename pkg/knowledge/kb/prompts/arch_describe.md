---
op: arch_describe
description: Describe the architectural role of a cluster of related modules
language_hint: any
output_format: markdown
schema: 'free-form markdown, max 6 paragraphs'
max_tokens: 4096
---
You are describing the architectural role played by a cluster of related
modules within an application. Focus on responsibilities, boundaries,
and how this cluster cooperates with the rest of the system.

Cluster modules (JSON):

{cluster_json}

Write up to 6 paragraphs of markdown. Do not return JSON.
