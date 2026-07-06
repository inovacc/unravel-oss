/*
Copyright (c) 2026 Security Research
*/

// Package xaml extracts XAML resources from WinUI/UWP applications: raw .xaml
// files, PE-embedded XAML in RT_RCDATA, and XBF binary (decoded by the xbf
// subpackage in plan 04). Produces XAMLEntry records aggregated into
// winui.XAMLIndex.
//
// The walker enforces depth, total file-size, and symlink guards by default;
// see WalkOptions. Symlink rejections and directory-level errors land in
// XAMLIndex.Errors. Per-file errors land in XAMLEntry.Errors so callers can
// distinguish "skipped" from "parsed but problematic" entries.
package xaml
