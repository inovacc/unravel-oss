/*
Copyright (c) 2026 Security Research
*/
package constantpool

import (
	"testing"

	"github.com/inovacc/unravel-oss/pkg/java/decompiler/classfile/reader"
)

func TestRead_NoEntries(t *testing.T) {
	r := reader.NewReader([]byte{})
	// JVM spec: constant_pool_count = N+1 (1-indexed). count=1 means
	// zero entries — must succeed on an empty buffer.
	pool, err := Read(r, 1)
	if err != nil {
		t.Fatalf("count=1 (zero entries): %v", err)
	}
	if pool == nil {
		t.Fatal("nil pool for zero-entry read")
	}
}

func TestRead_TruncatedFails(t *testing.T) {
	// count=2 means one expected entry; empty buffer must fail.
	r := reader.NewReader([]byte{})
	if _, err := Read(r, 2); err == nil {
		t.Error("expected error reading from empty buffer with count=2")
	}
}
