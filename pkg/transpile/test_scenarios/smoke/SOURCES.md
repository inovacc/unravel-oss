# Smoke Corpus Sources (D-03 / SC3)

This directory holds a **vendored, pinned, license-clean** smoke corpus used by
`internal/orchestrator/smoke_corpus_test.go` to assert the recover-guards
(Plan 08-03, Task 1) hold on real-world-shaped source: **zero panics** and
**zero silent unit drops** (`units_in == units_out`, every unit either produces
output or a surfaced audit error).

Per 08-RESEARCH §SC3, the corpus is **vendored, not fetched at test time** (CI
determinism), each project is small (< ~5 KLOC), has no build-system
dependency, and is license-clean (these fixtures are original minimal
implementations of common, well-known data-structure / utility patterns,
released under this repository's BSD-3-Clause license — no upstream code is
copied verbatim, so there is no third-party license to track).

| Lang | File | Description | Provenance | License | Pinned |
|------|------|-------------|------------|---------|--------|
| C++ | `cpp/stringutil.cpp` | String utility helpers (to_lower/trim/split/join) | Original minimal fixture authored for this corpus | BSD-3-Clause (repo) | Plan 08-03 commit |
| Python | `python/textstats.py` | Text statistics + LineBuffer class | Original minimal fixture authored for this corpus | BSD-3-Clause (repo) | Plan 08-03 commit |
| Java | `java/Stack.java` | Generic bounded stack | Original minimal fixture authored for this corpus | BSD-3-Clause (repo) | Plan 08-03 commit |

## Pinning

The corpus is pinned by **this repository's git history**: the files are
committed as the D-03 deliverable in Plan 08-03 and only change via an explicit
follow-up commit. There is no external upstream to track a SHA against because
the fixtures are original (no verbatim third-party source vendored), keeping
the corpus small and license-clean as 08-RESEARCH §SC3 requires.

## Adding a real upstream subset later

If a larger real OSS subset is added, record here: upstream repo URL, the exact
upstream commit SHA, the upstream license (must be MIT/BSD/Apache), and the
subset of paths vendored. Never add a build-system dependency or a large tree.
