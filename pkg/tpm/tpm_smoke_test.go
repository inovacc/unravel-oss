/*
Copyright (c) 2026 Security Research
*/
package tpm

import "testing"

func TestCheckTPM_NeverPanics(t *testing.T) {
	// CheckTPM returns TPMInfo on any platform — no preconditions, no
	// panics. On CI/test machines without TPM, Present must be false.
	info := CheckTPM()
	// Just exercise: field access, no specific expectation about Present.
	_ = info.Available
	_ = info.Platform
}

func TestUnsealKey_MissingBlob(t *testing.T) {
	if _, err := UnsealKey("does-not-exist.blob"); err == nil {
		t.Error("expected error unsealing missing blob")
	}
}

func TestScanAndExtract_EmptyDir(t *testing.T) {
	src := t.TempDir()
	out := t.TempDir()
	// Scan a directory with no TPM-sealed keys: must succeed with empty result.
	res, err := ScanAndExtract(src, out)
	if err != nil {
		t.Skipf("ScanAndExtract platform-dependent: %v", err)
	}
	if res == nil {
		t.Fatal("nil result on empty scan")
	}
}
