# pkg/inject/linux — Output Schema

This package emits `inject.Seam` records via
`inject.ScanWithPlatform(ctx, appDir, "linux")`. Each seam corresponds to
one ELF dynamic-section entry (DT_NEEDED, DT_RPATH, or DT_RUNPATH) and
carries Phase 25's ptrace-eligibility classification fields.

## Phase 25 schema additions

These fields are additive on `inject.Seam` and only populated by the
linux scanner. Phase 24 macOS seams and the Windows scanner output are
unchanged.

### `ptrace_eligible_binary` (`*bool`, omitempty)

Whether the binary's *static attributes* permit a Frida `ptrace` attach.
Three states:

| Value | Meaning |
|-------|---------|
| `true`  | Setuid bit not set on the file. ptrace attach is permitted by binary attrs alone. |
| `false` | Setuid bit set. Linux kernel blocks ptrace attach unless the attaching process holds `CAP_SYS_PTRACE`. |
| absent / `null` | Binary attrs unreadable (e.g., `os.Stat` failed). |

### `ptrace_flags` (`[]string`, omitempty)

Advisory list of binary attrs observed during classification. These are
informational only — they do **NOT** change `ptrace_eligible_binary`.
Emitted alphabetically:

| Flag | Meaning |
|------|---------|
| `non_pie`           | Binary is `ET_EXEC` (non-position-independent). Older binary lineage. |
| `pt_gnu_stack_exec` | `PT_GNU_STACK` segment is executable (PF_X bit set). Older binary lineage. |
| `static_linkage`    | No `PT_INTERP` program header. Statically linked. Reduces dynamic-injection vectors but ptrace itself remains possible. |

### `ptrace_eligible_binary_note` (`string`, omitempty)

Fixed disclaimer text (Phase 25 decision D-14). Appears on every seam
whose `ptrace_eligible_binary` is non-nil. Emitted verbatim:

```
host ptrace_scope policy (kernel.yama.ptrace_scope) applies at runtime; check via /proc/sys/kernel/yama/ptrace_scope before attempting attach
```

## Host-side runtime concern (explicitly NOT captured)

The Linux kernel applies an additional runtime policy via
`/proc/sys/kernel/yama/ptrace_scope` (the Yama LSM). Values:

- `0` — classic ptrace permissions (any process under the same UID).
- `1` — restricted: only ancestors / declared tracers (`PR_SET_PTRACER`).
- `2` — admin-only: requires `CAP_SYS_PTRACE`.
- `3` — no attach: ptrace disabled at the kernel level.

This is a **host-side runtime concern**, not a binary attribute. The
Phase 25 scanner deliberately does **NOT** read
`/proc/sys/kernel/yama/ptrace_scope` during scan, because:

1. The scanner may run on a different host than the eventual Frida target.
2. Reading `/proc` introduces non-determinism in scan output.
3. False certainty about host policy is worse than no certainty.

Frida autogen (Phase 26) is responsible for emitting a runtime preflight
that reads `/proc/sys/kernel/yama/ptrace_scope` when the script runs.

## Cross-platform note

- macOS (Phase 24) seams do not populate any of the three Phase 25
  fields — they remain nil/empty/`""`. JSON `omitempty` keeps the keys
  out of macOS output entirely.
- Windows seams likewise emit none of these fields.
- Top-level `ScanResult.Seams` is preserved for back-compat (D-23 from
  Phase 24). Linux seams appear both flattened in `Seams` and grouped
  under `Arches[0].Seams` (single-arch wrap, CONTEXT D-09).
