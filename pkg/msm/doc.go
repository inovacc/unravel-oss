/*
Copyright (c) 2026 Security Research
*/

// Package msm provides parsing of Windows Installer Merge Modules (.msm).
//
// A merge module is an OLE2/CFBF container holding an MSI relational database —
// the same container format as an .msi — but identified by a ModuleSignature
// table rather than product properties. Merge modules are designed to be merged
// into a parent .msi at build time and frequently bundle kernel drivers
// (OpenVPN DCO, WireGuard, etc.). This package reuses pkg/msi's CFBF + MSI table
// decoder via msi.OpenDatabase and surfaces the merge-module metadata, the
// Component/File listings, driver-file classification, and the embedded cabinet
// streams that carry the payload.
package msm
