# pkg/aihost — cross-host plugin packaging

<!-- rev:002 -->

`pkg/aihost` renders unravel's plugin (commands, agents, skills) and installs it
into each supported AI host. It is self-contained: **no `anthropic-sdk-go`, no
`embed.FS`, no MCP-transport or supervisor imports.**

## Contract

- **`Host`** (`host.go`): `Name()`, `InstallTarget()`, and `TreeWriter` (`Walk` +
  `ManifestFiles`, `write_tree.go`).
- **Optional capabilities** (type-asserted): `Installer` (Install/Uninstall),
  `Status` (PrintStatus), `Doctor` (DoctorReport).
- **`WriteTreeAtomic`** (`write_tree.go`): shared tmp+rename tree writer with
  stale-sweep, used by hosts without a bespoke installer.
- **Portable libraries** (`portable_libraries.go`): synthesized
  `unravel-command-library` / `unravel-agent-library` SKILL.md so commands and
  agents stay discoverable on skills-only hosts (codex, gemini).

## Assets

Assets are Go raw-string literals: `assets/<domain>/*.go` calls `RegisterAsset`
in `init()`; `assets/all/all.go` blank-imports every domain. `Kind` is inferred
from the path prefix (`commands/`, `agents/`, `skills/`). `Render(TemplateData)`
fills `<% %>` template fields and closes the frontmatter block.

## Hosts

| Host | Package | Surface |
|------|---------|---------|
| Claude Code | `claude/` | full install (marketplace + hooks.json + settings) |
| OpenAI Codex CLI | `codex/` | skills-only tree + `.codex-plugin/plugin.json` + `.mcp.json` |
| Gemini CLI | `gemini/` | skills-only tree + `gemini-extension.json` (inline mcpServers) |

## Adding a new host

1. Create `pkg/aihost/<name>/host.go` implementing `aihost.Host`:
   - `Name() string`                       — short id ("claude", "gemini", ...).
   - `InstallTarget() (string, error)`     — absolute path under `$HOME`.
   - `Walk(fn func(path, data) error) error` — render + emit each asset.
   - `ManifestFiles() (map[string][]byte, error)` — synthesised manifests.
2. In `init()`, call `aihost.Register(func() aihost.Host { return Host{} })`.
3. Pull portable assets via `aihost.AssetByPath(kind, path)` and render
   each with your host's `TemplateData`.
4. Add `_ "unravel/pkg/aihost/<name>"` to `pkg/aihost/all/all.go`.
5. CLI dispatcher (`aihost.All()` / `aihost.ByName()`) picks it up.

## Install paths

| Host   | Personal install                                  | Marketplace registration                              |
|--------|--------------------------------------------------|------------------------------------------------------|
| Claude | `~/.claude/plugins/marketplaces/<name>/`         | `claude plugin marketplace add <path>`               |
| Codex  | `~/.codex/plugins/<name>/`                       | `~/.agents/plugins/marketplace.json`                 |
| Gemini | `~/.gemini/extensions/<name>/`                   | `gemini extensions install <path>` (or symlink)      |

## Spec sources

- Claude:  https://code.claude.com/docs/en/plugins.md
- Codex:   https://developers.openai.com/codex/plugins/build
- Gemini:  https://github.com/google-gemini/gemini-cli/tree/main/docs/extensions

## Before you touch this package

Read **MAINTAINERS.md** (invariants) and **AUTHORING-RULES.md** (how to add/edit
an asset).
