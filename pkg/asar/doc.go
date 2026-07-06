/*
Copyright (c) 2026 Security Research
*/

// Package asar parses and extracts Electron ASAR archives.
//
// ASAR is the archive format used by Electron applications to bundle
// application source code. This package provides functions to open,
// parse, extract, and search ASAR files.
//
// Entry points:
//   - OpenAndParse: open an ASAR file and parse its header
//   - CollectFiles: flatten the header tree into a file list
//   - Extract: extract all files to a directory
//   - ReadFileContent: read a single file's content by offset
//   - Search: search all files for a text pattern
package asar
