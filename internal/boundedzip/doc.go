// Package boundedzip wraps archive/zip with size caps, symlink rejection, and
// zip-slip path validation for hardening attacker-supplied archive extraction.
//
// Default caps:
//   - MaxPerFile = 16 << 20 (16 MiB) — parity with pkg/winui/xaml/xbf.MaxTableSize.
//   - MaxTotal   = 64 << 20 (64 MiB) — parity with pkg/winui/xaml/pri.MaxFileSize.
//
// Mitigations applied at every extracted entry:
//   - per-file size cap (rejects zip-bomb single-entry overflow)
//   - cumulative total cap (rejects multi-entry zip-bomb overflow)
//   - symlink rejection via os.FileMode bits
//   - zip-slip rejection via filepath.Clean + HasPrefix
//
// Closes audit-M-3 (bounded archive extraction) and audit-L-1 (symlink rejection)
// generalising the per-decoder caps in pkg/winui to all zip extraction sites in
// pkg/msix, pkg/android/apk, and cmd/{android,dex2class}.
//
// Located at module-root internal/ (not pkg/internal/) so cmd/* packages can
// import it; Go's "internal" rule restricts pkg/internal to pkg/* importers.
package boundedzip
