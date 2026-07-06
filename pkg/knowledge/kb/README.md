# pkg/knowledge/kb

Internal building blocks for the `unravel knowledge` command. The four
subpackages here were extracted from `cmd/knowledge_*.go` so the command
layer stays thin and the SQL / parsing / scanning logic is reusable from
`pkg/mcptools` and unit-testable in isolation.

## Subpackages

| Package | Role | Imports |
|---------|------|---------|
| `db` | Opens `knowledge.db` (SQLite, `modernc.org/sqlite`) and applies the embedded `schema.sql`. Exposes `Open(path) (*sql.DB, error)` and the raw `Schema` string. | `database/sql` |
| `scanner` | Pure functions that parse JS bundles. Three entry points (`ScanMeta`, `ScanWebpack`, `ScanSingle`) plus `Promote` (synthesised-name → searchable name) and `Symbols` (high-signal substrings → JSON). No I/O. | stdlib only |
| `llm` | Wraps the local `claude` CLI (`Call`) and extracts JSON from its stdout (`ParseJSON`, `ExtractFirstJSONArray`). | `os/exec`, stdlib |
| `store` | Typed read queries against the catalog: `Search`, `Dump`, `Pending`, `Facts`, `Gaps`, `Stats`. All take `*sql.DB`; no globals. | `database/sql` |

Sibling `pkg/knowledge/registry` holds the YAML-defined fact schema that
`gaps`/`fill` materialise into `app_facts`. It is loaded via
`registry.Load("")`.

## Layering

```
cmd/knowledge.go
  ├── pkg/knowledge/kb/db        (open DB)
  ├── pkg/knowledge/kb/scanner   (sweep / dissect)
  ├── pkg/knowledge/kb/llm       (enrich / fill / ask)
  ├── pkg/knowledge/kb/store     (search / dump / stats / facts / gaps)
  └── pkg/knowledge/registry     (gaps registry → app_facts rows)
```

`cmd/` is the only caller of these packages today. `pkg/mcptools` will
import `store` (and only `store`) when the MCP catalog tools land.

## Adding a new `knowledge` subcommand

1. Add a new `case "<name>":` arm in `runKnowledge` in `cmd/knowledge.go`
   and a one-line description in the usage block at the top.
2. If the new arm needs to read the catalog, prefer adding a typed query
   to `kb/store` rather than inlining SQL in `cmd/`. Keep the function
   signature `func Foo(db *sql.DB, ...) ([]FooRow, error)`.
3. If it needs to call `claude`, reuse `llm.Call` + `llm.ParseJSON` —
   never re-implement the env-stripping invocation or the balanced-brace
   extractor.
4. Add a test in the relevant `kb/<pkg>_test.go`. Use `db.Open(":memory:")`
   for store tests and table-driven cases for parsing tests.
5. Run `go test ./pkg/knowledge/...` — tests must pass before the new
   subcommand is wired up.

## Test coverage

| Package | Coverage |
|---------|----------|
| `kb/db` | 72.7% |
| `kb/llm` | 67.7% (Call shells out, not covered) |
| `kb/scanner` | 83.5% |
| `kb/store` | 94.2% |
| `registry` | 80.5% |

Coverage gaps that are intentional: `llm.Call` (subprocess), and
`scanner` size-truncation paths reachable only with multi-megabyte
inputs.
