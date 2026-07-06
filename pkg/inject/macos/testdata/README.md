# Mach-O Test Fixtures

## Strategy: Programmatic byte fixtures (CONTEXT D-17/18 cost fallback)

Instead of committing pre-built `.app` bundles or thin Mach-O binaries,
Phase 24 builds minimal Mach-O byte sequences inside
`testdata_helpers_test.go` and writes them to `t.TempDir()` per test.
Rationale:

- <5 KB synthesized stubs per fixture are too small to be worth
  versioning.
- Hand-written bytes are auditable in the test source.
- No external toolchain (`clang`, `lipo`, `codesign`) needed in CI.

## Fixture catalogue

| Helper | Layout | Used by |
|--------|--------|---------|
| `buildThinARM64Stub` | thin Mach-O 64-bit ARM64 with one LC_LOAD_DYLIB + one LC_LOAD_WEAK_DYLIB + one LC_RPATH | `walker_test.go` |
| `buildFatX86_64ARM64Stub` | fat header wrapping two thin ARM64 slices | `walker_test.go: TestWalkFat` |
| `buildHardenedThinStub` | thin Mach-O 64-bit ARM64 + LC_CODE_SIGNATURE pointing at a SuperBlob whose CodeDirectory `flags = 0x10000 \| 0x2000` | `walker_test.go: TestWalkThin_Hardened` |

Real `.app` round-trip tests are out of scope for Phase 24 — see
CONTEXT D-19 (fixture strategy).
