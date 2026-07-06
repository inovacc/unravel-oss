/*
Copyright © 2026 Security Research
*/

// Package cert extracts and analyzes code-signing certificates from PE and ELF binaries.
//
// Supported binary formats:
//   - PE (Portable Executable): Authenticode PKCS#7 signatures from .exe and .dll files
//   - ELF (Executable and Linkable Format): kernel module appended signatures (.ko),
//     section-embedded certificates (.so), and ELF metadata extraction
//
// File type is auto-detected by magic bytes (MZ for PE, \x7fELF for ELF).
//
// Entry points:
//   - ExtractCertificates: parse any supported binary and return certificate info
//   - VerifyCertificate: extract and verify signature validity
//   - ScanDirectory: recursively find and analyze all signed binaries
//   - ExportPEM / ExportDER: write extracted certificates to disk
//   - GenerateReport / GenerateBatchReport: produce markdown reports
package cert
