/*
Copyright (c) 2026 Security Research
*/

// Package chromium extracts data from Chromium-based application profiles.
//
// It reads SQLite databases (cookies, history, Web Data), blob storage,
// and Local State files. Requires CGO for SQLite access.
//
// Build constraint: cgo
//
// Entry points:
//   - Extract: full extraction from a Chromium profile directory
//   - ExtractBlobStorage: extract blob storage files
//   - ExtractDatabases: extract data from SQLite databases
//   - ExtractCookies: extract and parse cookies database
package chromium
