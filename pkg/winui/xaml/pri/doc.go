/*
Copyright (c) 2026 Security Research
*/

// Package pri implements a read-only parser for Windows resources.pri
// (Package Resource Index) files. PRI is the binary format used by
// AppX/MSIX packages to ship localizable string and image resources.
//
// This implementation is best-effort and conservative: every offset is
// bounds-checked, the input is hard-capped at 64 MiB, and exotic payload
// types (large embedded blobs) surface as opaque blob references rather
// than being decoded inline. Recursion through section name resolution
// is bounded by a 16-hop visit set to mitigate circular-reference DoS
// (T-04-04).
//
// The format is undocumented by Microsoft; this implementation follows
// the community PriTools / mspriinfo references. Unknown sections are
// recorded but not faulted — drift across SDK versions is expected.
package pri

// MaxFileSize caps Parse / ParseBytes input. Inputs larger than this
// are rejected before any decode work begins.
const MaxFileSize int64 = 64 << 20 // 64 MiB

// MaxSectionVisits bounds the per-resolution visit set when walking
// section name references (T-04-04 mitigation).
const MaxSectionVisits = 16

// MaxResources caps the number of PRIResource entries returned. Large
// PRIs may declare tens of thousands of resources; an overflow warning
// is appended when the cap is hit.
const MaxResources = 10000

// MaxBlobInline is the upper inline-decode size for binary blob payloads.
// Larger payloads are recorded as a "blob:<offset>:<size>" reference
// instead of being copied into PRIResource.Value.
const MaxBlobInline = 64 * 1024
