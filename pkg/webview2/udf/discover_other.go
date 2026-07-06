//go:build !windows

/*
Copyright (c) 2026 Security Research
*/

package udf

// policyUDFCandidates is a no-op on non-Windows (registry is Windows-only).
func policyUDFCandidates() []string { return nil }
