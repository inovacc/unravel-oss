# goresym testdata fixtures

Committed Go binaries used by the symbol-recovery tests: the default,
dependency-free pure-Go parser tests in `recover_pure_test.go` (no build tag)
and the `//go:build goresym` CLI-backend live-recovery tests. Each fixture pins
a specific recovery outcome; the ELF ones are further characterized in
`docs/design/2026-goresym-backend.md`.

## `app_linux_stripped`

A plain `-s -w` stripped Go ELF. GoReSym recovers 136 user functions
(including `main.main`) from the pclntab even though the symtab/DWARF are
gone. Used by `TestRecover_LiveStrippedELF`. Provenance is recorded in the
design doc §3–§4.

## `app_linux_garbled`

A **garble-obfuscated** Go ELF — the headline mission target (an obfuscated
binary, not merely a stripped one). Used by `TestRecover_LiveGarbledELF` and
characterized in design doc **§O1**.

| Field | Value |
|-------|-------|
| Tool | `garble build` (default flags; no `-literals`/`-tiny`) |
| garble version | `mvdan.cc/garble v0.16.0` |
| Go toolchain | `go1.26.4` |
| GOOS / GOARCH | `linux` / `amd64` |
| Size | 1,675,390 bytes (~1.6 MB) |
| sha256 | `61e3ddd2d7dd6d817c7156099e2f89acb16470a9bc1b765ac29fb08a896bc107` |

### Source summary

A tiny self-contained `package main` (module `garblefixture`) with a named
struct `widgetConfig`, a named user function `computeChecksum`, a
`(widgetConfig).describe` method, and a `main` that calls them.

### Build command (reproducible)

```sh
# in an isolated temp dir (NOT the repo) containing main.go + go.mod
go mod init garblefixture
GOOS=linux GOARCH=amd64 garble build -o app_linux_garbled .
```

### Expected recovery (pinned)

`GoReSym v1.7.1` **fails** on this binary:

```
{"error": "Failed to parse file: failed to read pclntab: failed to locate pclntab"}
```

i.e. **zero** functions/types are recovered. Garble relocates/obfuscates the
pclntab+moduledata, defeating GoReSym v1.7.1's pclntab signature scan on
Go 1.26 targets — whereas the *same source* built with plain `-s -w`
stripping (`app_linux_stripped`) recovers 136 functions. The `-literals -tiny`
garble variant fails identically. The backend surfaces this as a real wrapped
error (not `ErrNotImplemented`), so dissect records it in `r.Errors` and
continues. See design doc §O1 for the operator takeaway.

## `app_windows_stripped.exe`

A `-s -w -trimpath` stripped **PE** (Windows) Go binary. Committed to guard the
pure-Go PE recovery path — the `imageBase + VirtualAddress` textStart math and
the whole-file `rawScan` (Go puts the pclntab in an unnamed `.rdata` region on
PE, so the named-section locator never fires). The ELF fixtures exercise neither.
Used by `TestRecoverPure_StrippedPE`; `recoverPure` recovers the three user
functions `main.main`, `main.greet`, `main.add` (plus stdlib when requested).

| Field | Value |
|-------|-------|
| Tool | `go build -ldflags "-s -w" -trimpath` |
| Go toolchain | `go1.26.4` |
| GOOS / GOARCH | `windows` / `amd64` |
| Size | 1,667,072 bytes (~1.6 MB) |
| sha256 | `5e420f7a766ec0904bf32d7f946b27fa0588c617bd107cddccfafe8322ba4457` |

### Source summary

A tiny self-contained `package main` (module `petiny`) with `main`, a
`greet(name string) string`, and an `add(a, b int) int`. `greet`/`add` are
`//go:noinline` so the compiler keeps them as distinct pclntab entries (trivial
funcs would otherwise be inlined into `main` and never appear in the table).

### Build command (reproducible)

```sh
# in an isolated temp dir (NOT the repo) containing main.go + go.mod (module petiny)
GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" -trimpath -o app_windows_stripped.exe .
```

```go
// main.go
package main

import (
	"fmt"
	"os"
)

func main() { fmt.Fprintln(os.Stdout, greet("unravel"), add(2, 3)) }

//go:noinline
func greet(name string) string { return "hello, " + name }

//go:noinline
func add(a, b int) int { return a + b }
```
