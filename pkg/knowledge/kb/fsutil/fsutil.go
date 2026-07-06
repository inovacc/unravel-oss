// Package fsutil provides Windows-safe filesystem helpers for the unravel
// knowledge-base store. All KB-store I/O routes through this package so that
// reserved-character handling, MAX_PATH wrapping, and store-root resolution
// stay in one place.
//
// Exports:
//   - EncodeKsID  — DB-form ks_id ("<kb_id>:<version>:<captured_at>") to a
//     filesystem-safe folder name ("<kb_id>_<version_safe>_<captured_at>").
//   - WrapLongPath — Windows-only \\?\ prefix when the path exceeds the
//     MAX_PATH-style threshold; no-op on POSIX.
//   - KBStoreRoot  — resolve the kb-store root from $UNRAVEL_KB_STORE or
//     <user-home>/unravel/kb-store/.
package fsutil
