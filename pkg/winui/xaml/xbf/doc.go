/*
Copyright (c) 2026 Security Research
*/

// Package xbf implements a pure-Go decoder for XBF (Microsoft.UI.Xaml binary
// format) v2.1 — the WinUI 3 / Windows 10+ era compiled XAML container.
//
// The decoder follows the placeholder-on-unknown-opcode contract laid out in
// Phase 4 CONTEXT.md decision D-08: the format is undocumented, opcode drift
// across SDK versions is expected, and every unknown opcode is rendered as an
// XML comment placeholder rather than aborting the stream. The decoder also
// never panics on malformed input: every offset/length read is bounds-checked
// with uint64 arithmetic, and a defer/recover at DecodeXBFBytes upgrades any
// missed condition into an error return.
//
// Reference (READ-ONLY, do NOT vendor):
//
//	https://github.com/misenhower/XbfAnalyzer  (C#, archived; v2.1 schema)
//	O'Reilly XAML Unleashed §3.3 "Binary XAML"
//	Microsoft.UI.Xaml.Markup.XamlBinaryWriter docs (confirms format name).
//
// Round-trip is human-readable, NOT byte-identical: XBF strips whitespace and
// comments at compile time, so the recovered .xaml mirrors the structure of
// the original source but not its formatting.
package xbf
