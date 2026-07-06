# pkg/aihost — MAINTAINERS

<!-- rev:001 -->

Read this before changing anything under `pkg/aihost`. These are load-bearing.

1. **D-09 (MCP-only AI).** This package MUST NEVER import
   `github.com/anthropics/anthropic-sdk-go`. Only `internal/ai/` and
   `internal/mcp/` may. `task d09:check` (path-based AST guard) fails the build
   otherwise. AI happens via the MCP sampling seam, never here.
2. **No `embed.FS`.** Assets are Go raw-string literals only. Do not add embedded
   files. To embed a backtick inside a raw-string body, break out with
   `` ` + "`literal`" + ` `` concatenation seams.
3. **Frontmatter must end with `\n`.** `Render()` writes the frontmatter verbatim
   then appends `---\n` (and, for skills, `created:`) with NO separating newline.
   A frontmatter string that does not end in `\n` produces a malformed asset.
   Guarded by `TestAssets_FrontmatterEndsWithNewline`.
4. **Capabilities are optional, type-asserted.** A host implements `Host`, and
   opts into `Installer`/`Status`/`Doctor` by defining those methods. Do not fold
   them into `Host`.
5. **Every registered asset must pass `TestRegisteredPromptAssetsLint`** (renders,
   has frontmatter + non-blank description, no secret tokens). Add an asset →
   run the lint.
6. **Provenance.** lensr's `pkg/aihost` was ported from this package; when
   backporting lensr maturity, adapt (unravel bindings, `assets/<domain>` scheme),
   never copy lensr's asset content or `pkg/agents` runtime.
