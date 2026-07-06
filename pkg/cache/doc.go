/*
Copyright (c) 2026 Security Research
*/

// Package cache parses Chromium HTTP cache directories (Simple Cache and Block File formats).
//
// It detects the cache format automatically, extracts cached responses with
// headers and metadata, and provides a formatted summary.
//
// Entry points:
//   - DetectFormat: identify cache format (simple or block-file)
//   - Parse: parse all entries from a cache directory
//   - FormatSummary: human-readable summary of parsed results
package cache
