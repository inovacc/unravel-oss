/*
Copyright (c) 2026 Security Research
*/

// Package dpapi decrypts Windows DPAPI-protected data from Chromium profiles.
//
// It extracts the AES master key from Local State, then uses it to decrypt
// cookies and saved passwords stored in Chromium SQLite databases.
//
// Build constraints: windows && cgo
//
// Entry points:
//   - ExtractMasterKey: extract AES key from Chromium Local State file
//   - DecryptCookies: decrypt encrypted cookie values
//   - DecryptPasswords: decrypt saved login credentials
package dpapi
