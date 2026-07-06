/*
Copyright (c) 2026 Security Research
*/

// Package resources provides Android resources.arsc parsing and APK assets analysis.
//
// This package extracts metadata from Android application packages:
//   - Global string pool from resources.arsc
//   - Package name and resource type names
//   - Assets inventory with categorization
//   - WebView and database detection
//
// The ARSC parser focuses on extracting the global string pool and package metadata
// without performing full resource resolution. Asset scanning categorizes files by
// type and detects security-relevant patterns like embedded databases and WebView content.
package resources
