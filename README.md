<!-- generated-by: gsd-doc-writer -->
# Unravel

Universal forensic teardown engine for desktop and mobile applications — a single Go binary that dissects Electron, Tauri, Java, Android, .NET, WebView2, WinUI, UWP, iOS, MSI/MSIX/RPM/DEB packages, and more to produce knowledge bases thorough enough to replicate features and generate security reports.

## What This Is

Unravel is a security research CLI and MCP server focused on **complete knowledge extraction** from any binary: reconstructed source, visual captures, decompiled classes, beautified JS, decrypted data. It ships everything in one cross-platform `unravel` binary (Windows, Linux, macOS), prefers pure Go, and uses CGO only for Chromium SQLite and Windows DPAPI.

The project targets stealth-class apps and protected runtimes — Cluely, OpenCluely, Pluely, Perssua and their kin — where screen-capture protection, content-protected windows, and packed bundles defeat normal inspection tooling. Detection is recipe-driven via `manifests/default.yaml`; analyzers self-register through `init()` into the dispatch table in `pkg/dissect/`.

AI is **MCP-only**. The `internal/ai/` and `internal/mcp/` packages are the sole importers of `github.com/anthropics/anthropic-sdk-go`; everything else delegates through the MCP sampling seam (`internal/mcp/sampling.go`). This invariant is enforced by `task d09:check` and gated in CI.

## Quick Start

```bash
# Build the single binary (pure Go)
go build .

# Auto-detect and dissect any input
go run . dissect ./app.apk -o ./report
go run . dissect ./MyApp.exe --debug

# Knowledge extraction + scorecard
go run . knowledge build ./input/cluely -o ./kb
go run . kb query ./kb --surface ipc

# Start the MCP server (stdio)
go run . mcp serve
```

## Key Features

- **Dissect pipeline** (`pkg/dissect/`) — auto-detect → cache check → dispatch → analyzers → cache store
- **Knowledge extraction** — `pkg/knowledge/` builds queryable KBs; `pkg/knowledge/scorecard` produces deeply-cited SCRG-01..05 scorecards with per-frame NDJSON sidecars and `_score.json` envelopes
- **Active code injection** — Frida AI enrichment + post-capture validation (shipped v2.7)
- **Visual capture** — production CDP frame source with per-frame NDJSON writer (v2.11)
- **Per-framework analyzers** — Android (APK/AAB/APKM/XAPK), Electron+ASAR, Tauri, .NET, Java, JS bundle reconstruction, WinUI 3, UWP/MSIX, WebView2, MSI/NSIS/DEB/RPM
- **Stealth detection** — `setContentProtection(true)` (Electron) and `allow-set-content-protected` ACL (Tauri) recognition
- **Certificate forensics** — PE Authenticode + ELF kernel module signatures
- **Browser extension forensics** — scan, analyze, export across Chromium browsers
- **Chromium extraction** (CGO) — LevelDB, HTTP cache, cookies, profile data; Windows DPAPI decryption
- **173 MCP tools** exposed via Model Context Protocol; tool count is an enforced invariant (`TestToolCountInvariant`)
- **Supervisor singleton** (v2.17) — `internal/supervisor/` runs one long-lived process per user; MCP processes dial it over UDS / named pipe with 48 verbs across 10 domains. Auto-spawns on first MCP connect.
- **Debug recorder** — `--debug` dumps every intermediate artifact to `debug/YYYY-MM-DD_HH-MM-SS/`

## Build & Install

```bash
# Default (no CGO)
go build .

# With CGO (enables chromium + dpapi commands)
CGO_ENABLED=1 go build .

# Opt out of TPM support
go build -tags notpm .

# Install to $GOPATH/bin
go install .
```

Requirements: Go 1.25+ (the module pins the Go 1.26.4 toolchain via `go.mod`, which `go` will fetch automatically). Optional: Java runtime for external RE tools (`apktool`, `jadx`, `dex2jar`), .NET for `ilspycmd`. See `scripts/install-tools.sh` for the RE tool installer.

### Taskfile

The repo uses [Task](https://taskfile.dev). Common targets:

| Task | Purpose |
|------|---------|
| `task build` | Build the binary into `./bin/` |
| `task test` | `go test ./...` (Docker-free; latest measured coverage 55.0%) |
| `task ci:test` | Local parity with CI quality-check job |
| `task ci:full` | `d09:check` + lint + tests |
| `task d09:check` | Enforce MCP-only AI invariant |
| `task lint` | `golangci-lint run --fix ./... --timeout=5m` |
| `task check` | fix + fmt + vet + lint + test |

Run `task --list` for the full set.

## Usage

```bash
unravel --help                         # full command tree
unravel app dissect <path> [-o out] [--ai] # auto-dispatch analyzers
unravel kb enrich generate <path>      # extract knowledge base
unravel kb catalog search <query>      # search an extracted KB
unravel mcp serve [--no-autospawn]     # MCP server (stdio; dials the supervisor singleton)
unravel app inject <pid|path>          # active code injection (Frida)
unravel android info ./app.apk         # framework-specific entry points
unravel asar extract ./app.asar -o .   # Electron archives
unravel winui analyze ./MyApp/ --json  # WinUI 3 / XBF v2.1 decoder
unravel uwp analyze ./pkg.msix --json  # UWP / MSIX capability scoring
unravel goversions sync|list|info|verify|cve  # Go release catalog: per-version artifacts + sha256 checksums, release dates/notes, and vuln.go.dev CVE posture; lazy 24h refresh
```

Integration tests (ephemeral postgres via testcontainers-go):

```bash
go test -tags=integration ./pkg/knowledge/kb/... ./pkg/mcptools/...
```

## MCP Integration

Unravel exposes **~173 tools** through the Model Context Protocol. The MCP tool registry lives in `pkg/mcp/tools/`. The recommended install path is the unravel Claude Code plugin (below) — it registers the MCP server via a plugin-shipped `.mcp.json` (spec form) so Claude Code auto-starts it.

## Claude Code Plugin

The unravel CLI ships a Claude Code plugin (commands + subagents + skill) embedded directly in the binary. Install with:

```bash
go install .
unravel plugin install --host claude
```

This writes the plugin to `~/.claude/plugins/marketplaces/unravel/`, patches `~/.claude/settings.json` `enabledPlugins`, and registers the marketplace via `claude plugin marketplace add`. Restart Claude Code to load.

**Shipped slash commands** (autocomplete after restart):
- `/unravel:build` — end-to-end KB build (dissect → backfill → enrich → verify)
- `/unravel:enrich` — AI enrichment for pending modules (Task fan-out)
- `/unravel:doctor` — plugin + KB + MCP health check
- `/unravel:pending` — backlog by app
- `/unravel:retry` — retry failed enrichments
- `/unravel:verify` — sample-verify recent enrichments
- `/unravel:vendored` — detect repeat-hash vendored chunks
- `/unravel:help` — argument tables for every command

**Shipped subagents** (invoke via `Task` tool with `subagent_type="unravel:<name>"`):
`unravel-enricher`, `unravel-kb-builder`, `unravel-dissector`, `unravel-self-healer`, `unravel-code-extractor`, `unravel-style-extractor`, `unravel-reassembler`, `unravel-mapper`, `unravel-cleanroom-porter`.

Plugin source of truth: `pkg/aihost/claude/assets.go` (Go raw-string literals, no `embed.FS`, no upstream markdown directory). Cross-host abstractions for OpenAI Codex CLI and Google Gemini CLI live under `pkg/aihost/codex/` and `pkg/aihost/gemini/` (Walk + ManifestFiles only; Install + Doctor TODO).

For standalone MCP usage without the plugin, the binary's `.mcp.json` form is:

```json
{
  "mcpServers": {
    "unravel": {
      "command": "unravel",
      "args": ["mcp"]
    }
  }
}
```

## Status

- **Current shipped:** v2.17.1 (supervisor host-singleton daemon)
- **v2.13 highlights:** MCP sampling pivot — `claude --print` subprocess path removed (`internal/ai/llm`); CLI `knowledge enrich/fill/ask` surface deleted; active enrichment is now the `unravel-plugin` Claude Code plugin orchestrating Task-spawned `unravel-enricher` subagents via MCP I/O tools (`unravel_kb_enrich_pending` + `unravel_kb_enrich_write_enrichment` + `unravel_kb_enrich_record`)
- **v2.12 highlights:** KBC-ENRICH-SESSION-MONITOR (enrich_runs + enrich_attempts + `_status`/`_retry` MCP tools, resume within 10min heartbeat)
- **Phases delivered:** 65+ across v2.1 → v2.13
- **Open carryovers:** `v2.12-CARRYOVER-SCRG-05-DEEPENING` (behavior tolerance widening); KB-CONSUMPTION Phase D–G — see `docs/BACKLOG.md`
- **Architectural ratifications:** ADR-0006, ADR-0007, ADR-0008 (see `docs/adr/`)

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — dissect pipeline, daemon, debug recorder
- [`docs/MCP_USAGE.md`](docs/MCP_USAGE.md) — MCP tool reference and Claude Code integration
- [`docs/MILESTONES.md`](docs/MILESTONES.md) — phase-by-phase shipped feature history
- [`docs/TESTING.md`](docs/TESTING.md) — Docker-free and integration test workflows
- [`docs/BACKLOG.md`](docs/BACKLOG.md) — future work and carryovers
- [`docs/adr/`](docs/adr/) — Architecture Decision Records
- [`CLAUDE.md`](CLAUDE.md) — conventions and load-bearing project rules

## License

MIT — see [LICENSE](LICENSE).
