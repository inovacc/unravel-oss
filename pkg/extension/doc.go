/*
Copyright (c) 2026 Security Research
*/

// Package extension provides browser extension forensics for Chromium-based browsers.
//
// It discovers extensions across Chrome, Edge, Brave, Opera, Vivaldi, and Chromium,
// parses manifests, analyzes permissions by risk level, scans source code for
// suspicious patterns, and detects stealth/cheating tools.
//
// Entry points:
//   - DiscoverBrowsers: find all Chromium browser profiles with extensions
//   - ScanAllExtensions: full discovery and analysis across all browsers
//   - AnalyzeSingleExtension: deep analysis of one extension by ID or path
//   - ExtractExtensionData: extract files + forensic metadata from ID/path/package
//   - SearchExtensions: cross-extension pattern search
//   - ExportAllExtensions: bulk export with beautified JS and reports
package extension
