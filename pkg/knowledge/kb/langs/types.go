// Package langs is the pluggable per-language extractor registry that the
// `unravel knowledge ingest` walker uses to convert a source file on disk
// into a Module ready to be persisted via the same INSERT path that
// `unravel knowledge index` already drives.
//
// All extractors are pure: no DB, no filesystem access. The walker reads
// the file once and hands the bytes to the extractor.
package langs

// Module is the in-memory shape produced by an extractor. It mirrors
// what the JS sweep already persists (modules + module_sightings +
// module_bodies), plus the source-code-only fields `Lang` and `Imports`.
type Module struct {
	// Name is the display name of the module — for Go this is
	// "<package>.<filename>" (e.g. "knowledge.knowledge"). The walker
	// makes it unique per file via the (app, body_sha256) UNIQUE.
	Name string

	// BodyExcerpt is the first 4 KB of the body, indexed for pg_trgm search.
	BodyExcerpt string

	// BodySHA256 is the hex-encoded sha256 of the FULL body bytes.
	BodySHA256 string

	// FullBody is the pristine bytes of the source file, written into
	// module_bodies once per unique sha256.
	FullBody []byte

	// SymbolsJSON is a JSON object of {"functions":[...], "types":[...], ...}
	// produced by the per-language extractor. Covered by the pg_trgm index.
	SymbolsJSON string

	// Prefix is the first directory segment of the file relative to the
	// repo root (e.g. "pkg" for "pkg/foo/bar.go"). Used as a coarse
	// filter bucket, mirroring the WAWeb-prefix convention from the
	// JS sweep.
	Prefix string

	// Lang is the language tag — "go", "js", "ts", "py", etc. Persisted
	// to modules.lang. Empty for the generic fallback.
	Lang string

	// Imports lists the dependency strings declared by the source file.
	// The walker stores them on module_deps (resolution against sibling
	// modules happens in a later pass; for v1 the strings are persisted
	// verbatim).
	Imports []string

	// Size is the byte length of the full body. Persisted to body_size.
	Size int
}

// ExtractFn turns a single source file into a Module. The path is the
// absolute filesystem path (used by some extractors to derive Name);
// body is the file contents already loaded into memory.
type ExtractFn func(path string, body []byte) (Module, error)
