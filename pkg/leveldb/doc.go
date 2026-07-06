/*
Copyright (c) 2026 Security Research
*/

// Package leveldb parses LevelDB databases used by Electron and Chromium applications.
//
// It reads .ldb data files, .log write-ahead logs, and MANIFEST/CURRENT files
// to extract key-value entries stored by web applications in Local Storage.
//
// Entry points:
//   - ParseDirectory: parse all files in a LevelDB directory
//   - ParseLogFile: parse a single .log file
//   - ParseLDBFile: parse a single .ldb file
//   - FormatSummary: human-readable summary of parsed results
package leveldb
