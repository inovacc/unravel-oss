# Changelog

All notable changes to **unravel** are documented here. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the
project does not strictly follow semver — minor versions ship features.

## [Unreleased] — v2.17 (in progress)

### Breaking

- **Supervisor singleton replaces the legacy MCP-→-gRPC bridge.** A
  single long-lived `unravel daemon` process now owns the Postgres pool
  + cross-session state; per-session MCP processes dial it as thin
  clients over UDS (POSIX) or named pipe (Windows). The
  `unravel mcp serve --daemon` flag is gone; replaced by
  `unravel mcp serve --no-autospawn` (sense inverted — when set, MCP
  refuses to autospawn the daemon and returns
  `ErrSupervisorUnavailable` instead). 48 verbs across 10 domains
  (kb, enrich, drift, capture, agent, session, workspace, daemon,
  lifecycle, store).
- **`unravel_kb_export` response shape changed.** Emits
  `kbstore.ExportPayload` (in-memory DB rows only) instead of
  `{bundle_dir, bundle_path, manifest, packed, manifest_path}` — bundle
  packaging is now CLI-only via `unravel knowledge export --bundle`.
  External MCP callers consuming `bundle_path` / `manifest_path` must
  switch to the CLI.
- **`unravel_kb_doctor` response shape changed.** Drops `resolved_db`
  and `text` (supervisor never reveals server-side identity over IPC);
  emits the `kbstore.DoctorReport` payload plus a top-level `source`
  field recording where the DSN originated.
- **`unravel_kb_timeline` no longer resolves alias kb_ids.** Aliased
  ids now return a supervisor not-found error; callers must pass the
  canonical id (use `kb_apps` / `kb_resolve` to look it up).
- **`unravel_plugin_doctor` `db.open` PASS detail simplified.** Now
  reads "supervisor pool reachable" instead of the prior
  `user@host:port/db` DSNDisplay() string. The supervisor intentionally
  never reveals server-identity over IPC.

### Added

- **Windows console-popup suppression** in detach + autospawn + WebView2
  host. `CREATE_NO_WINDOW` flag plus `HideWindow: true` on every
  `exec.CommandContext` spawn (tasklist, taskkill, powershell, WebView2
  Spawn). The daemon and capture flows no longer flash conhost.exe
  windows during heavy operation.
- **`kb.search` filter + cursor expansion.** Now supports `component`,
  `topic`, `fact_type`, `lang`, `since_millis`, and opaque-cursor
  pagination at the supervisor seam — `unravel_kb_search` MCP tool keeps
  its existing wire shape (query / returned / next_cursor / items[] /
  enrichment_coverage_pct / fallback_used / fallback_banner).
- **`daemon.doctor` verb + DaemonClient.** Server-side aggregation of
  the four DB-touching probes that `plugin_doctor` previously did
  inline (ping, kbstore.Stats, enrich_runs total / stale / last_run_at).
- **`kb.vendored_candidates` verb** backing the existing
  `unravel_kb_vendored_candidates` MCP tool — closes the loop on the
  `/unravel-vendored` plugin command.

### Changed

- All `pkg/mcp/tools/` MCP handlers route through
  `internal/supervisor/clients/` (KBClient, EnrichClient, DriftClient,
  CaptureClient, DaemonClient). The package-level `kbDB` pool will be
  removed in a follow-up commit before tagging v2.17.0.
- Tool count stable at 157 across the whole refactor — no MCP tools
  were added or removed.

## [Unreleased] — v2.15 (in progress)

### Added

- **KBC Phase D Phase 2 — opus-retry orchestration in enrich SKILL.md.**
  Grafted the model-escalation protocol section into the
  `skills/enrich/SKILL.md` plugin asset (`pkg/aihost/claude/assets.go`).
  The enrich subagent now retries with opus after 3 sonnet failures
  on the same module, and flags `needs_human_verification` when opus
  also fails. Completes KBC-ENRICH-MODEL-ESCALATION (Go data plane
  shipped in v2.14, prompt layer shipped here).
- **KBC Phase G — drift detection.** New `pkg/knowledge/drift/`
  package (pure Go, no LLM) computes four per-run metrics
  (success_rate, escalation_rate, human_review_rate,
  mean_cost_micro_usd) from `enrich_runs` + `enrich_attempts` +
  `modules`, compares against a per-app baseline using relative-delta
  thresholding (default ±20% with a 0.01 floor to avoid near-zero
  blow-ups), and persists drift events to a new `drift_alerts` table
  paired with `slog.Warn`. Auto-triggers at the end of every
  `unravel kb enrich` run unless `--no-drift` opt-out is set;
  non-fatal — drift errors never fail the enrich run. Three new
  MCP tools (`unravel_kb_drift_check`, `unravel_kb_drift_baseline`,
  `unravel_kb_drift_history`) and CLI subcommands
  (`unravel kb drift-check`, `drift-baseline {set,clear,show}`,
  `drift-history`). Tool count 154 → 157. Schema migration 000017
  adds `enrich_attempts.cost_micro_usd`, `enrich_runs.baseline_for`
  (with unique partial index), and `drift_alerts` table.

## [v2.14] — 2026-05-24

**Scope decision:** ships now. Phase D2 SKILL.md graft (subagent
opus-retry orchestration) + Phase E pgvector embeddings deferred to
v2.15 — both are independently meaningful and don't gate the v2.14
deliverables. Owner decision unblocks v2.15 (Phase E needs hosted-
embedding endpoint choice; Phase D2 needs the markdown graft).

### Added

- **Transpile pipeline activated.** 120 .go files at `pkg/transpile/`
  (analysis, archive, audit, core/{adapt,codegen,converter,debug,ir},
  grammar, languages/{cpp,java,python,typescript}, rules, strategies)
  + 9.5 MB testdata + test_scenarios. Default build links the
  package; gated `//go:build togo_active` dropped.
- **`unravel_kb_diff_apps`** MCP tool — cross-app behavioural diff
  over enriched modules. `{app_a, app_b, category?, limit?}` →
  `{a_only, b_only, common_count}`. Pure SQL. KBC Phase F.
- **`unravel_knowledge_enrich_human_review`** MCP tool — list +
  `mark_resolved` actions for the `modules.needs_human_verification`
  flag. KBC-ENRICH-MODEL-ESCALATION Phase 1.
- **`unravel_insights_record` / `_start_goal` / `_complete_goal`**
  MCP tools + `unravel_plugin_doctor` MCP tool — surface 153 → 154
  (six tools added across the v2.14-prep arc; tool-count invariant
  bumped atomically).
- **Self-improvement insights pipeline** (Phases 1-6): jsonl event
  capture (Cobra invocations + MCP-tool calls + Task dispatches),
  per-goal jump counting, monthly rollup with median/p95/max jumps,
  6 heuristic suggestion rules (high_retry_rate, high_failure_rate,
  high_friction_goal, dead_command, frequent_failure_message,
  no_goals_closed), `unravel insights {status,rollup,suggest,accept,
  rotate,wipe}` CLI, gzip rotation, session-id env propagation,
  storage root at `%LOCALAPPDATA%\Unravel\insights\improving` (also
  XDG/Library on Linux/Mac).
- **Cross-host plugin packaging** (`pkg/aihost/{claude,codex,gemini}`)
  with `Host` + optional `Installer` / `Status` / `Doctor` capabilities
  via type-assertion. Auto-marketplace register: codex (direct JSON
  patch of `~/.agents/plugins/marketplace.json`), gemini (shell-out
  to `gemini extensions install`), claude (CLI `claude plugin
  marketplace add`).
- **`.NET Windows Service` file type** (`TypeDotNetService`) +
  `detectDotNetDir` directory dispatcher wiring `pkg/dotnet/
  IsWindowsService` (ASP.NET Core ref / Generic Host / *Service.exe
  / *Worker.exe heuristics). 5 new detect tests. Phase 16 carryover
  closed.
- **`StripBundlerBoilerplate`** (`pkg/jsdeob/strip_bundler.go`) —
  strips 5 full-line patterns of webpack/esbuild/rollup/vite runtime
  cruft. Preserves user code + webpack `.d(...)` export tables +
  string-literal collisions. New `Options.StripBundlerCruft` switch.
  6 new tests. Phase 11 carryover closed.
- **Schema migration 000015** — `modules.needs_human_verification`
  (bool, default false) + `modules.escalated_to` (text, CHECK IN
  ('opus')) + partial index for fast `_human_review` tool scans.
- **`unravel_kb_write_enrichment`** MCP tool: additive
  `escalated_to` + `needs_human_verification` fields propagated by
  the subagent's retry orchestrator. Validates `escalated_to='opus'`
  on the way in.

### Changed

- **KB search ranking (KBC-VI-RECALL fix).** `pkg/knowledge/kb/
  store/store.go` ORDER BY now weights `name` (×2.0) + `summary`
  (×1.5) above the generic `search_text` trigram (×1.0). Enriched +
  semantic-named modules surface at default `--limit`. Integration
  test `TestSearch_NameWeightedRanking` guards the new ranking
  contract.
- **PendingModules WHERE clause** excludes `needs_human_verification
  = true` rows so flagged modules drop out of normal enrichment runs.
- **Decompiler `pkg/java/decompiler/`** wholesale-replaced from togo
  (owner-authored canonical source). 43 vendor files reconciled;
  9 unravel-specific `*_smoke_test.go` files preserved; `compare/`,
  `patterns/`, `hybrid.go` preserved; "Decompiled with togo" header
  brand-stripped to "with unravel". 13/13 decompiler subpackage
  tests pass. `pkg/java/decompiler/_vendor/` deleted.
- **`go.mod`** new direct deps: `github.com/antlr4-go/antlr/v4
  v4.13.1`, `github.com/dominikbraun/graph v0.23.0`,
  `golang.org/x/tools v0.43.0` (transitive: `golang.org/x/tools/
  imports`). Added by `go mod tidy` once the transpile gated build
  surfaced the imports.
- **`pkg/aihost/claude/assets.go`** — 4 "## Status DEFERRED" blocks
  removed from `unravel-transpiler` + `unravel-codebase-analyst`
  agent definitions (transpile pipeline compiles by default now;
  warnings no longer accurate).

### Fixed

- **Critical `/tools/` gitignore bug** (commit 20a0ab78 earlier in
  the v2.14-prep arc) — bare `tools/` matched `pkg/mcp/tools/` at
  any depth, silently losing 90 MCP-tool files from git after the
  `pkg/mcptools/` → `pkg/mcp/tools/` rename. Anchored to `/tools/`
  (repo root only); 90 files recovered.
- **3 stale `cmd/` tests** — `TestKbMerge_MissingConfig`,
  `TestResolveDSN/ErrorWhenConfigMissing`,
  `TestKnowledgeHelpGolden/root`. Expectations updated `unravel db
  setup` → `unravel setup kb` (2026-05-23 rename); help golden
  regenerated (155-byte drift).
- **3 stale `pkg/mcp/tools/` tests** —
  `TestDocsToolCountConsistent`, `TestMCPRegistry_8NewTools`,
  `TestP60ScopeGuard` referenced legacy `pkg/mcptools/` path
  (122bcbea rename legacy). `filepath.Join` arg lists updated;
  `p60BaselineMCPFileCount` 56 → 64.
- **`TestSemantic_KnowledgeEnrich_Deprecated`** removed — asserted
  against an `unravel_knowledge_enrich` deprecation-redirect stub
  that the v2.13 plugin pivot fully removed. Test failed with
  "unknown tool".
- **6 transpile test failures** post-lift —
  `pkg/transpile/languages/{java/parser,python/lower,python/parser}/`
  "open testdata: not found". Vendored `testdata/` (728 files,
  9.5 MB) + `test_scenarios/` from owner's sibling tree; patched
  4-up relative paths to 3-up.
- **THIRD_PARTY_NOTICES.md** purged of togo MIT attribution (owner-
  authored, not third-party). File retained as canonical attribution
  location for future external code.

### Phase reclassifications

After the post-v2.14-prep roadmap triage:

- Phase 10 IN PROGRESS → **COMPLETE**
- Phase 14 IN PROGRESS → **COMPLETE**
- Phase 11 IN PROGRESS → MOSTLY COMPLETE → **COMPLETE** (jsdeob
  enhancement shipped this release)
- Phase 16 IN PROGRESS → MOSTLY COMPLETE → **COMPLETE** (Windows-
  service detection shipped this release)
- Phase 9 IN PROGRESS → **MOSTLY COMPLETE** (Android emulator
  integration deferred)
- Phase 18 IN PROGRESS → **MOSTLY COMPLETE** (WAR/EAR enterprise
  tests deferred)

Net active scope after v2.14: **Phase 12 + 13 IN PROGRESS, Phase 9
+ 18 MOSTLY COMPLETE**.

### Deferred to v2.15

| Item | Owner action required |
|------|-----------------------|
| KBC Phase E — pgvector embeddings | Pick hosted embedding endpoint (Anthropic / OpenAI / Cohere / Voyage). See `docs/superpowers/specs/2026-05-24-kbc-phase-e-g-execution-notes.md` |
| SCRG-05-DEEPENING | `/gsd:debug` on F-69-07 dim regression first |
| Phase 9 — Android emulator integration | AVD/Genymotion harness + Frida inject scripts |
| Phase 18 — WAR/EAR enterprise tests | Acquire 2-3 real WAR/EAR samples |
| Phase 12 — node network interception + MCP-as-client + Frida Node | each its own mini-phase |
| Phase 13 — full typosquat depth + maintainer indicators | Registry-API integration |

### Known issues (pre-existing, not v2.14 introduced)

- **`pkg/knowledge/kb/store/store_test.go` integration tests fail
  on `:memory:` SQLite DSN.** Pre-existing infra bug (introduced
  2026-05-20, commit `f2085558`). `kbdb.Open` is postgres-only; the
  `newDB` helper passes `:memory:`. Affects 11 store tests +
  several `pkg/mcp/tools/` integration tests. Default `-short` tests
  are unaffected. Filed in BACKLOG as `DEBT-STORE-INMEMORY-DSN`.

### Verification

- `go build ./...` clean.
- `task d09:check` clean (MCP-only invariant intact).
- `go test -short ./...` green on all session-touched packages.
- `go vet ./...` clean.
- `golangci-lint run` zero issues on session-touched paths.
- MCP tool count: **154** (was 148).
- DB migrations: **15** (was 14; `000015_enrich_human_review` added).

---

## [v2.13] — 2026-05-23

MCP sampling pivot — `claude --print` subprocess path removed; CLI
surface `knowledge enrich/fill/ask` deleted; active enrichment path
is the `unravel-plugin` Claude Code plugin orchestrating Task-spawned
`unravel-enricher` subagents via MCP I/O tools
(`unravel_kb_pending_enrich` + `unravel_kb_write_enrichment` +
`unravel_kb_enrich_record`). Phase 20 TPM/registry/DPAPI dumps all
shipped. MCP tool count 148.

---

## [v2.12] — 2026-05-20

KBC-ENRICH-SESSION-MONITOR — `enrich_runs` + `enrich_attempts` tables
+ `_status` / `_retry` MCP tools, resume within 10-min heartbeat.

---

## Earlier versions

See `git tag` for the v2.3 — v2.11 history.
