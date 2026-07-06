/*
Copyright (c) 2026 Security Research
*/

// Package overlay merges a static knowledge bundle with a live capture
// bundle, annotating every leaf with provenance metadata (_source,
// _capture_ts, optional _static_value). Pure-data: no filesystem or
// network I/O.
//
// Per Phase 23 D-08: live wins on conflict; original static value is
// archived as _static_value for diff inspection.
//
// Per Phase 23 D-09: provenance fields are additive and only present
// when the live overlay is invoked. Static-only paths never call this
// package and remain byte-equivalent to v2.3.
package overlay
