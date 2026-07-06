/*
Copyright (c) 2026 Security Research
*/
package knowledge

import "github.com/inovacc/unravel-oss/pkg/aihost"

func init() {
	aihost.RegisterAsset(
		aihost.Asset{
			Path: "agents/unravel-kb-builder.md",
			Frontmatter: `name: unravel-kb-builder
description: |
  End-to-end knowledge-base builder for unravel. Spawned by /unravel:build,
  walks the full pipeline: framework detection -> bundle dissect -> Postgres
  KB row population -> static backfill -> AI enrichment fan-out via
  unravel-enricher children -> sample verification -> coverage delta report.
  Use when the user wants to ingest a new app into the KB, or bring an
  existing app to a coverage target.
`,
			Body: `# unravel-kb-builder

End-to-end orchestrator that turns an Electron / Tauri / WinUI / .NET /
Java desktop bundle into a fully-summarised entry in the unravel Postgres
knowledge base. You delegate the heavy lifting to the unravel CLI and
to ` + "`unravel-enricher`" + ` subagent children spawned via Task. You do NOT
call any model yourself outside that delegation.

## Inputs

You receive arguments in the prompt as ` + "`key=value`" + ` tokens:

| arg            | meaning                                                       |
|----------------|-----------------------------------------------------------------|
| app            | KB app slug (teams, whatsapp, slack, ...)                     |
| path           | absolute path to bundle (required if app not in KB yet)       |
| enrich         | 0 or 1 - run AI enrichment fan-out (default 1)                |
| enrich_limit   | per-pass module count (default 100, hard cap 100)             |
| enrich_passes  | how many limit-sized passes to chain (default 1)              |
| audit          | 0 or 1 - run auto self-check after enrichment (default 0)     |
| verify         | 0 or 1 - sample-verify after enrichment (default 1)           |
| dry_run        | 0 or 1 - plan only, no writes (default 0)                     |
| vendor_omit    | 0 or 1 - identify vendored libs, save only the package name,  |
|                | and exclude them from enrichment (default 1)                  |

## Pipeline phases

### Phase 1 - DETECT (~5s)

Output line: ` + "`framework=<X> exists_in_kb=<bool> db=ok`" + `.

Preflight: if the input is a lone artifact (a bare .dll/.jar/.wasm/.exe with
no app manifest), do NOT abort — the capture path synthesizes a minimal
fingerprint (platform from file type + name). Prefer the headless
` + "`unravel kb build <path>`" + ` verb, which handles this and the full chain.

### Phase 2 - INGEST (1-15 min, depends on bundle size)

Output: ` + "`ingested=<N> modules total=<M>`" + `.

### Phase 3 - STATIC BACKFILL (~30s per 1000 modules)

Output: ` + "`static_complete=true vendored_candidates=<N>`" + `.

### Phase 3.5 - CLASSIFY: vendor + triage

Output: ` + "`vendored_packages=<P> omitted=<M> static=<S> enrich_queue=<E>`" + `.
If modules with open contradictions exist, prioritize them in the ` + "`enrich_queue`" + `.

### Phase 4 - ENRICH

Route each pending module by language BEFORE fanning out:
- JavaScript / TypeScript bodies -> spawn ` + "`unravel-enricher`" + ` (Task).
- Java / .NET / Kotlin / smali / dex / native (.node) / WASM bodies ->
  spawn ` + "`unravel-enricher-poly`" + ` (Task).
Use the module's stored lang/name to pick; when unknown, default to
unravel-enricher-poly (its tools degrade gracefully on JS too).

Output cumulative: ` + "`enriched_total=<N> failed_total=<N>`" + `.
If ` + "`audit=1`" + `, trigger ` + "`/unravel:audit-kb auto=1`" + ` for each batch.

### Phase 5 - VERIFY

Output: ` + "`verified=<N> opaque_rate=<X percent>`" + `.

### Phase 6 - REPORT

## Required commands (run via Bash)

` + "`unravel app detect`" + `, ` + "`unravel app dissect`" + `, ` + "`unravel kb catalog apps`" + `,
` + "`unravel kb catalog stats`" + `, ` + "`unravel kb ops doctor`" + `, ` + "`unravel kb enrich pending`" + `,
` + "`unravel kb enrich write-enrichment`" + `,
` + "`unravel kb catalog search`" + `, ` + "`unravel kb gaps list`" + `,
` + "`unravel kb enrich classify`" + `.

Vendored-candidate detection (` + "`unravel_kb_vendored_candidates`" + `) and the
cross-run regression check (` + "`unravel_kb_ops_regression_check`" + `) have no
dedicated CLI subcommand yet — use ` + "`unravel kb catalog query`" + ` with a
` + "`GROUP BY body_sha256 HAVING COUNT(*) >= N`" + ` aggregate for the former, and
` + "`unravel kb transfer diff-dirs`" + ` (compare two knowledge output
directories) as the closest regression-style check for the latter.

Tools: Task (for unravel-enricher AND unravel-enricher-poly fan-out), Bash, Read.
`,
		},
		aihost.Asset{
			Path: "commands/build.md",
			Frontmatter: `description: End-to-end KB build for an app - dissect, backfill, enrich, verify via unravel-kb-builder subagent
argument-hint: [app=<name>] [path=<path>] [enrich=0|1] [enrich_limit=N] [enrich_passes=N] [audit=0|1] [verify=0|1] [dry_run=0|1] [help=0|1]
allowed-tools: [Task, Bash, Read]
`,
			Body: `# /unravel:build

> ⚠️ **Deprecated (2026-07-04).** Use ` + "`/unravel:kb`" + ` instead. This alias
> forwards to the same ` + "`unravel-kb-builder`" + ` pipeline and will be removed
> after **2026-08-04** (30-day window). If you invoked this, note the
> deprecation and prefer ` + "`/unravel:kb path=<...>`" + ` going forward.

End-to-end KB build for an unravel-tracked app. Delegates the full
pipeline to the ` + "`unravel-kb-builder`" + ` subagent (identical behavior to
` + "`/unravel:kb`" + `).
`,
		},
		aihost.Asset{
			Path: "agents/unravel-ks-manager.md",
			Frontmatter: `name: unravel-ks-manager
description: |
  Semantic code storage manager for Knowledge Sources. Treats every
  application capture as a managed Git repository, providing built-in
  versioning, traceability, and deduplication. Coordinates between the
  filesystem (SVC layer) and the Postgres catalog.
`,
			Body: `# unravel-ks-manager

Knowledge source lifecycle manager. Your role is to ensure code is
stored semantically using a service-oriented approach.

## Required commands (run via Bash)

` + "`unravel kb catalog apps`" + `, ` + "`unravel kb catalog sources`" + `, ` + "`unravel kb enrich ingest`" + `,
plus Task, Bash, Read, Write.
`,
		},
		aihost.Asset{
			Path: "commands/capture-svc.md",
			Frontmatter: `description: Perform a semantically optimal code capture into a Git-managed Knowledge Source via unravel-ks-manager subagent
argument-hint: [app=<slug>] [path=<src>] [version=<v>] [message=<msg>] [help=0|1]
allowed-tools: [Task, Read, Write, Bash]
`,
			Body: `# /unravel:capture-svc

Semantic code capture. Initializes or updates a managed Git repository
in the KB store for the target application. Delegates to the
` + "`unravel-ks-manager`" + ` subagent.
`,
		},
		aihost.Asset{
			Path: "agents/unravel-kb-query.md",
			Frontmatter: `name: unravel-kb-query
description: |
  Natural-language query agent over the KB. Translates questions
  ("what calls module X", "which apps use setContentProtection",
  "find IPC handlers for trouter") into unravel CLI calls,
  aggregates results, returns a structured answer with citations
  to module ids.
`,
			Body: `# unravel-kb-query

Read-only KB query interpreter. Takes a natural-language question,
plans the CLI call sequence, executes via Bash, returns a structured answer.

## Required commands (run via Bash)

` + "`unravel kb catalog apps`" + `, ` + "`unravel kb catalog stats`" + `, ` + "`unravel kb catalog search`" + `,
` + "`unravel kb catalog dump`" + `, ` + "`unravel kb catalog facts`" + `, ` + "`unravel kb gaps list`" + `,
` + "`unravel kb catalog timeline`" + `, ` + "`unravel kb transfer diff`" + `.

Vendored-candidate detection has no dedicated CLI subcommand — use
` + "`unravel kb catalog query`" + ` with a ` + "`GROUP BY body_sha256`" + ` aggregate instead.
`,
		},
		aihost.Asset{
			Path: "commands/query.md",
			Frontmatter: `description: Natural-language KB query via unravel-kb-query subagent
argument-hint: [q=<question>] [app=<slug>] [limit=N] [help=0|1]
allowed-tools: [Task]
`,
			Body: `# /unravel:query

Natural-language query over the KB. Delegates to ` + "`unravel-kb-query`" + `.
`,
		},
		aihost.Asset{
			Path: "commands/kb.md",
			Frontmatter: `description: Build a complete KB from ANY artifact in one flow - dissect, capture, backfill, triage-gated enrich, verify via unravel-kb-builder
argument-hint: path=<file|binary|app|dir|bundle> [app=<name>] [enrich=auto|off|full] [stack-hint=<hint>] [resume=<token>]
allowed-tools: [Task, Bash, Read]
`,
			Body: `# /unravel:kb

The canonical one-flow: take ANY file, binary, app, directory or bundle and
produce a complete knowledge-base entry. Delegates the whole chain WHOLESALE to
the ` + "`unravel-kb-builder`" + ` subagent (do not reimplement it here).

## Arguments
- ` + "`path=`" + ` (required) - the artifact. Lone artifacts (.dll/.jar/.wasm/.exe) are accepted.
- ` + "`app=`" + ` - app slug; inferred from path/fingerprint if omitted.
- ` + "`enrich=auto|off|full`" + ` (default auto):
  - ` + "`auto`" + ` - triage-gated: only modules classed ENRICH run the LLM leg; STATIC_OK/SKIP get static-only.
  - ` + "`full`" + ` - enrich all pending modules.
  - ` + "`off`" + ` - capture + backfill only, no LLM.
- ` + "`stack-hint=`" + ` - optional framework hint passed to detection.
- ` + "`resume=`" + ` - resume token from a prior interrupted run.

## Flow
1. Spawn ` + "`unravel-kb-builder`" + ` with these args. It runs detect -> dissect ->
   capture (headless ` + "`unravel kb build`" + `) -> static backfill -> classify ->
   polyglot enrich fan-out -> sample verify -> coverage delta.
2. On enrich=auto, it routes JS -> unravel-enricher, else -> unravel-enricher-poly.
3. Report the coverage delta and any unresolved gaps.

Idempotent and resumable: safe to re-run; already-summarized modules are kept.
`,
		},
		aihost.Asset{
			Path: "skills/kb/SKILL.md",
			Frontmatter: `name: kb
description: Build a knowledge base from ANY dropped file, binary, app, or bundle. Invoke when the user says "build a KB for X", "reverse-engineer <binary>", "dissect this app", "ingest <path> into the KB", or drops a binary/app path and wants it fully analyzed. Picks the right analyzer per artifact type, runs detect -> dissect -> capture -> backfill -> classify -> enrich -> verify, and delegates the LLM enrichment leg to the existing enrich skill.
`,
			Body: `# kb — any artifact -> knowledge base

You are running the "build a KB from anything" workflow. Take the user's
artifact and produce a complete KB entry. Prefer the headless verb; fall back
to the command for the full agentic flow.

## Analyzer selection (artifact type -> path)
- Electron / ASAR (.asar, app.asar) ....... ` + "`unravel asar extract`" + ` -> kb build
- Tauri / native PE (.exe, .dll) .......... ` + "`unravel app dissect`" + ` -> kb build
- Java (.jar, .war, .class) ............... ` + "`unravel java decompile`" + `
- .NET (.dll managed, .exe) ............... ` + "`unravel dotnet decompile`" + `
- Android (.apk) .......................... ` + "`unravel android extract`" + ` + static subcommands
- iOS (.ipa) .............................. ` + "`unravel ios extract`" + `
- Native addon (.node) .................... ` + "`unravel nodeaddon symbols`" + `
- WASM (.wasm) ............................ ` + "`unravel wasm info`" + `
- Installers (.msi/.msix/.deb/.rpm) ....... ` + "`unravel <fmt> extract`" + `
- Lone/unknown artifact ................... ` + "`unravel kb build <path>`" + ` (synthesizes fingerprint)

## Flow
1. Detect the type (` + "`unravel app detect`" + `) if unsure.
2. Run ` + "`unravel kb build <path>`" + ` (headless: capture + backfill + classify).
   For a full agentic run with triage-gated enrichment, invoke ` + "`/unravel:kb`" + `.
3. For the enrichment leg, delegate to the existing **enrich** skill (do not
   duplicate it) — it fans out unravel-enricher / unravel-enricher-poly.
4. Verify via ` + "`unravel kb catalog stats`" + ` (coverage) and
   ` + "`unravel kb transfer diff-dirs`" + ` (regression-style comparison against a
   prior snapshot, when one exists) and report the coverage delta.

Idempotent and resumable. Never reject a lone artifact — the capture path
synthesizes a minimal fingerprint from the file type + name.
`,
		},
	)
}
