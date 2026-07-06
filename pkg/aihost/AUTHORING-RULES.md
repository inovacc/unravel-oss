# pkg/aihost — Asset Authoring Rules

<!-- rev:001 -->

How to add or edit a plugin asset (command / agent / skill).

## Where assets live

- One Go file per domain: `pkg/aihost/assets/<domain>/*.go`, registered via a
  single `aihost.RegisterAsset(...)` call in the domain's `init()`.
- New domain → add its blank-import to `pkg/aihost/assets/all/all.go`.
- `Kind` is inferred from the `Path` prefix — do NOT set it explicitly:
  - command → `Path: "commands/<name>.md"`
  - agent   → `Path: "agents/<name>.md"`
  - skill   → `Path: "skills/<name>/SKILL.md"`

## Frontmatter per Kind

- **Command:** `description`, `argument-hint`, `allowed-tools` — NO `name:` key.
  The `/unravel:` prefix appears only in the Body H1.
- **Agent:** `name`, `description` (no `tools:` key).
- **Skill:** `name`, `description` (the trigger blurb).
- **Every `Frontmatter` raw string MUST end with a newline** (`…\n` before the
  closing backtick). See MAINTAINERS §3.

## Body rules

- Reference only real MCP tools (`mcp__unravel__*`) and real sibling assets —
  no invented names.
- Backticks inside a raw-string body use `` ` + "`x`" + ` `` seams.
- Commands delegate to an agent; skills may delegate to another skill — do not
  duplicate logic across assets.

## After editing

Run: `go build ./... && go test ./pkg/aihost/...` — the lint
(`TestRegisteredPromptAssetsLint`), the presence test (`TestAssetsByPath_AllPresent`),
and the frontmatter guard (`TestAssets_FrontmatterEndsWithNewline`) all gate assets.
If you added a NEW asset path, add it to `wantPaths` in
`pkg/aihost/claude/assets_split_regression_test.go`.
