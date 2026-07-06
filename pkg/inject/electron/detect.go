/*
Copyright (c) 2026 Security Research
*/
package electron

// Detect is a package-level convenience wrapper exposing the package's
// scanner.Detect for callers that don't need the full Scanner interface
// (e.g. P57 framework gate). Pure scan-only per D-05.
func Detect(appDir string) bool { return scanner{}.Detect(appDir) }
