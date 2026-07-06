# ELF Test Fixtures

## Strategy: Programmatic byte fixtures (CONTEXT D-19/D-20)

Instead of committing pre-built ELF binaries or AppImage payloads,
Phase 25 builds minimal ELF byte sequences inside
`testdata_helpers_test.go` and writes them to `t.TempDir()` per test.
Rationale:

- <5 KB synthesized stubs per fixture are too small to be worth
  versioning as binary blobs.
- Hand-written bytes are auditable in the test source.
- No external toolchain (`gcc`, `ld`, `chmod 04755` survival across
  git checkout) needed in CI.

## Fixture catalogue

| Helper | Layout | Used by |
|--------|--------|---------|
| `buildThinX86_64WithRpath` | 64-bit x86_64 ELF, ET_DYN, PT_INTERP, .dynamic with one DT_NEEDED + one DT_RPATH | `walker_test.go: TestWalkELF_X86_64WithRpath`; ptrace eligibility=true path |
| `buildThinAarch64Setuid`   | 64-bit aarch64 ELF, ET_DYN, PT_INTERP, .dynamic with one DT_NEEDED. Test sets file mode to 04755 via `os.Chmod` at write time | `ptrace_test.go: TestClassifyPtrace_Setuid` (eligibility=false) |
| `buildThinX86_64Static`    | 64-bit x86_64 ELF, ET_EXEC, NO PT_INTERP segment, no .dynamic section | `ptrace_test.go: TestClassifyPtrace_Static` (advisory `static_linkage` flag) |

## Real fixtures (gated)

Real AppImage and `.deb`-extracted ELF round-trip tests live behind
`-tags=integration` and look for fixtures under `input/`. They skip
cleanly when absent — see CONTEXT D-21.
