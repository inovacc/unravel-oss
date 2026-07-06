/*
Copyright (c) 2026 Security Research
*/

// Package detect provides unified file type detection for the unravel toolkit.
//
// It identifies files by content (magic bytes, headers, structural checks) and
// maps each detected type to the applicable unravel commands. This enables a
// "scan directory -> identify everything -> run appropriate analysis" workflow.
//
// Entry points:
//   - Detect: identify a single file or directory
//   - Scan: recursively scan a directory and classify all files
package detect
