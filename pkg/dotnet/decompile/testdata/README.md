# decompile test fixtures

## Files

- `mockilspy/main.go` — Go-built stand-in for `ilspycmd`. Compiled in `TestMain`
  via `go build -o mockilspy(.exe)`; the resulting binary's directory is
  prepended to `PATH` before `m.Run()` so `exec.LookPath("ilspycmd")` resolves
  to the mock. Behavior selected via `MOCK_ILSPYCMD_MODE` env var:
  `ok | crash | garbage | hang | version`. Concurrency observation via
  `MOCK_ILSPYCMD_COUNTER_FILE` (lockfile-protected counter; max value tracked
  in second 8-byte slot).

- `minimal_managed.dll` — minimal valid managed PE with a CLR header. Build
  steps (run once, commit the result):

  ```bash
  echo 'public class E {}' > E.cs
  csc /target:library /out:minimal_managed.dll E.cs
  ```

  If `csc` is unavailable, `TestMain` synthesizes one in-place via the
  `debug/pe` writer-style helper in `managed_pe_test.go` (see
  `synthMinimalManagedPE`). The synthesized fixture sets
  `DataDirectory[14].VirtualAddress` non-zero so `IsManagedPE` returns true.

- `unmanaged.bin` — a non-CLR PE. Synthesized in `TestMain` via the same
  helper with `DataDirectory[14]` zeroed. The file MUST NOT contain a CLR
  header.

## Why a mock-ilspycmd binary

Real `ilspycmd` requires `dotnet` runtime + `dotnet tool install -g ilspycmd`,
which CI may not have. The mock lets us assert wrapper behavior (flag
forwarding, exit-code handling, stderr capture, timeout via
`exec.CommandContext`) without that prerequisite.

## Cleanup

The compiled mock binary lives only under `testdata/` and is removed by
`TestMain` after the suite runs.
