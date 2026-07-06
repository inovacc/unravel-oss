/*
Copyright (c) 2026 Security Research
*/
package constantpool

import (
	"testing"

	"github.com/inovacc/unravel-oss/pkg/java/decompiler/classfile/reader"
)

// TestRead_ZeroCountRejected feeds constant_pool_count == 0 (as a crafted .class
// would). Without a guard, count-1 underflows in uint16 to 65535 and allocates a
// 65535-element slice. Read MUST reject count==0 with an error. Finding #24.
func TestRead_ZeroCountRejected(t *testing.T) {
	r := reader.NewReader([]byte{})
	p, err := Read(r, 0)
	if err == nil {
		t.Fatalf("expected error for constant_pool_count==0, got nil")
	}
	if p != nil {
		t.Fatalf("expected nil pool on error, got non-nil with %d entries", len(p.entries))
	}
}
